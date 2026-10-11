use crate::packet_reader::PacketReader;
use crate::packet_writer::PacketWriter;
use crate::{
    query_attribute_capabilities, AsyncMysqlIntermediary, AsyncMysqlShim, CapabilityFlags, Column,
    ColumnFlags, ColumnType, CommandAllocationAdmission, InitWriter, OkResponse, ParamParser,
    ParsedBindings, QueryResultWriter, StatementMetaWriter, StatisticsSnapshot, StatisticsWriter,
    ValueInner,
};
use async_trait::async_trait;
use std::io;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::io::AsyncWrite;

#[tokio::test]
async fn initial_database_rejection_flushes_one_error_closes_and_never_dispatches_buffered_commands(
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for compression in [
        CapabilityFlags::empty(),
        CapabilityFlags::CLIENT_COMPRESS,
        CapabilityFlags::CLIENT_ZSTD_COMPRESSION_ALGORITHM,
    ] {
        let shim = FrontierShim {
            init_error: true,
            ..Default::default()
        };
        let disconnects = shim.disconnects.clone();
        let initializations = shim.initialization_calls.clone();
        let read_calls = shim.read_calls.clone();
        let commands = shim.command_frontiers.clone();
        let databases = shim.init_databases.clone();
        let (socket, mut peer) = tokio::io::duplex(8192);
        let (input, output) = tokio::io::split(socket);
        let server = AsyncMysqlIntermediary::run_on(shim, input, tokio::io::BufWriter::new(output));
        let client = async {
            let mut reader = PacketReader::new(&mut peer);
            let (seq, greeting) = reader.next_async().await.unwrap().unwrap();
            assert_eq!(seq, 0);
            assert_eq!(greeting[0], 10);
            drop(reader);
            let flags = CapabilityFlags::CLIENT_PROTOCOL_41
                | CapabilityFlags::CLIENT_PLUGIN_AUTH
                | CapabilityFlags::CLIENT_SECURE_CONNECTION
                | CapabilityFlags::CLIENT_CONNECT_WITH_DB
                | compression;
            let mut response = flags.bits().to_le_bytes().to_vec();
            response.extend_from_slice(&1024u32.to_le_bytes());
            response.push(8);
            response.extend_from_slice(&[0; 23]);
            response.extend_from_slice(b"login\0\0bad_\xe9\0mysql_native_password\0");
            if compression == CapabilityFlags::CLIENT_ZSTD_COMPRESSION_ALGORITHM {
                response.push(3);
            }
            let mut bytes = frame(&response);
            bytes[3] = 1;
            let handshake_end = bytes.len();
            bytes.extend_from_slice(&frame(b"\x03SELECT should_not_execute"));
            bytes.extend_from_slice(&frame(&[0x0e]));
            for &byte in &bytes[..handshake_end - 1] {
                peer.write_all(&[byte]).await.unwrap();
            }
            peer.write_all(&bytes[handshake_end - 1..]).await.unwrap();
            peer.flush().await.unwrap();
            let mut reader = PacketReader::new(&mut peer);
            let (seq, error) = reader.next_async().await.unwrap().unwrap();
            assert_eq!(seq, 2, "the original handshake response sequence");
            assert_eq!(error[0], 0xff);
            assert_eq!(u16::from_le_bytes(error[1..3].try_into().unwrap()), 1049);
            assert_eq!(&error[3..9], b"#42000");
            assert_eq!(&error[9..], b"actual backend database selection error");
            drop(reader);
            assert_eq!(
                peer.read(&mut [0; 1]).await.unwrap(),
                0,
                "ERR then EOF, no OK or PING"
            );
        };
        let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(server, client)
        })
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(disconnects.load(Ordering::SeqCst), 1);
        assert_eq!(initializations.load(Ordering::SeqCst), 0);
        assert_eq!(read_calls.load(Ordering::SeqCst), 0);
        assert!(commands.lock().unwrap().is_empty());
        assert_eq!(&*databases.lock().unwrap(), &[b"bad_\xe9".to_vec()]);
    }
}

fn raw_auth_change_packet(username: &[u8], database: &[u8], charset: u16) -> Vec<u8> {
    let mut payload = vec![0x11];
    payload.extend_from_slice(username);
    payload.push(0);
    payload.push(0); // Actual one-byte, empty native-password response.
    payload.extend_from_slice(database);
    payload.push(0);
    payload.extend_from_slice(&charset.to_le_bytes());
    payload.extend_from_slice(b"mysql_native_password\0");
    frame(&payload)
}

#[tokio::test]
async fn initial_authentication_borrows_raw_names_and_packet_charset_at_every_original_hook() {
    let cases: &[(u16, &[u8], &[u8])] = &[
        (8, b"caf\xe9", b"db_\xe9"),
        (28, b"\x81\x5c_user", b"db_\x81\x5c"),
        (45, "用户".as_bytes(), "数据库".as_bytes()),
        (45, b"bad_\xff", b"db_\xc3"),
        (0, b"'quoted_user'", b"raw_\xff"),
        (255, b"", b""),
    ];
    for &(charset, username, database) in cases {
        let capabilities = CapabilityFlags::CLIENT_PROTOCOL_41
            | CapabilityFlags::CLIENT_PLUGIN_AUTH
            | CapabilityFlags::CLIENT_SECURE_CONNECTION
            | CapabilityFlags::CLIENT_CONNECT_WITH_DB;
        let mut bytes = capabilities.bits().to_le_bytes().to_vec();
        bytes.extend_from_slice(&1024u32.to_le_bytes());
        bytes.push(u8::try_from(charset).unwrap());
        bytes.extend_from_slice(&[0; 23]);
        bytes.extend_from_slice(username);
        bytes.extend_from_slice(&[0, 0]); // Name terminator then empty response length.
        bytes.extend_from_slice(database);
        bytes.push(0);
        bytes.extend_from_slice(b"mysql_native_password\0");
        let (remaining, handshake) = crate::commands::client_handshake(&bytes, false).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(handshake.username.as_deref(), Some(username));
        assert_eq!(handshake.db.as_deref(), Some(database));
        let shim = FrontierShim::default();
        let names = Arc::clone(&shim.auth_names);
        let databases = Arc::clone(&shim.init_databases);
        let mut output = Vec::new();
        let mut intermediary = AsyncMysqlIntermediary {
            client_capabilities: capabilities,
            process_use_statement_on_query: false,
            reject_connection_on_dbname_absence: false,
            shim,
            reader: PacketReader::new(&[][..]),
            writer: PacketWriter::new(&mut output),
            zstd_compression_level: 0,
            secure_transport: false,
        };
        intermediary.init_after_ssl(handshake, 1).await.unwrap();
        assert_eq!(*databases.lock().unwrap(), [database.to_vec()]);
        let expected = [
            ("charset", vec![], charset, None),
            ("publish_charset", vec![], charset, None),
            ("plugin", username.to_vec(), charset, Some(true)),
            ("proof", username.to_vec(), charset, Some(true)),
            ("result", username.to_vec(), charset, Some(true)),
            ("authenticated", username.to_vec(), charset, Some(true)),
            ("admission", username.to_vec(), charset, Some(true)),
        ];
        assert_eq!(&*names.lock().unwrap(), &expected);
        drop(intermediary);
        let mut reader = PacketReader::new(output.as_slice());
        let (sequence, response) = reader.next_async().await.unwrap().unwrap();
        assert_eq!(sequence, 2);
        assert_eq!(response[0], 0);
        assert!(reader.next_async().await.unwrap().is_none());
    }
}

#[tokio::test]
async fn change_user_raw_names_and_charset_survive_dispatch_compression_and_next_ping() {
    use super::packet_reader::compression_frame;
    let cases: &[(u16, &[u8], &[u8])] = &[
        (8, b"caf\xe9", b"db_\xe9"),
        (28, b"gbk_\x81\x5c", b"db_\x81\x5c"),
        (45, "用户".as_bytes(), "数据库".as_bytes()),
        (45, b"bad_\xff", b"db_\xc3"),
        (65_535, b"raw_\xff", b"db_\xff"),
        (0, b"", b""),
    ];
    for compression in 0..=2 {
        for error in [false, true] {
            for first in 0..if error { cases.len() } else { 1 } {
                let cases = &cases[first..];
                let shim = FrontierShim {
                    change_user_error: error,
                    ..Default::default()
                };
                let names = Arc::clone(&shim.auth_names);
                let databases = Arc::clone(&shim.changed_databases);
                let executions = Arc::clone(&shim.command_executions);
                let entries = Arc::clone(&shim.change_user_entries);
                let disconnects = Arc::clone(&shim.disconnects);
                let reached = if error { 1 } else { cases.len() };
                let capabilities =
                    CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_PLUGIN_AUTH;
                let mut commands = Vec::new();
                for &(charset, username, database) in cases {
                    commands.push(raw_auth_change_packet(username, database, charset));
                    commands.push(frame(&[0x0e]));
                }
                commands.push(frame(&[0x01]));
                let input: Vec<u8> = commands
                    .iter()
                    .flat_map(|packet| {
                        if compression == 0 {
                            packet.clone()
                        } else {
                            compression_frame(0, packet, compression == 2)
                        }
                    })
                    .collect();
                let mut output = Vec::new();
                run_frontier(shim, &input, &mut output, capabilities, compression)
                    .await
                    .unwrap();
                let expected: Vec<_> = cases
                    .iter()
                    .take(reached)
                    .map(|&(charset, username, database)| {
                        (
                            username.to_vec(),
                            (!database.is_empty()).then(|| database.to_vec()),
                            charset,
                        )
                    })
                    .collect();
                assert_eq!(*databases.lock().unwrap(), expected);
                let expected_names: Vec<_> = cases
                    .iter()
                    .take(reached)
                    .flat_map(|&(charset, username, _)| {
                        [
                            ("charset", vec![], charset, None),
                            ("plugin", username.to_vec(), charset, Some(false)),
                            ("proof", username.to_vec(), charset, Some(false)),
                            ("result", username.to_vec(), charset, Some(false)),
                        ]
                    })
                    .collect();
                assert_eq!(
                *names.lock().unwrap(),
                expected_names,
                "CHANGE_USER checks before proof but never publishes the live charset before commit"
            );
                let mut expected_execution = Vec::new();
                for _ in 0..reached {
                    expected_execution.extend([(0x11, false), (0x11, true)]);
                    if !error {
                        expected_execution.extend([(0x0e, false), (0x0e, true)]);
                    }
                }
                if !error {
                    expected_execution.extend([(0x01, false), (0x01, true)]);
                }
                assert_eq!(*executions.lock().unwrap(), expected_execution);
                assert_eq!(entries.load(Ordering::SeqCst), reached);
                assert_eq!(disconnects.load(Ordering::SeqCst), 1);
                let mut replies = PacketReader::new(output.as_slice());
                if compression == 1 {
                    replies.enable_compression();
                } else if compression == 2 {
                    replies.enable_zstd_compression();
                }
                for _ in 0..reached {
                    let (sequence, response) = replies.next_async().await.unwrap().unwrap();
                    assert_eq!(sequence, 1);
                    if error {
                        assert_eq!(
                            response.as_ref(),
                            b"\xff\x19\x04#42000actual backend candidate database admission error"
                        );
                    } else {
                        assert_eq!(response[0], 0);
                    }
                    if !error {
                        let (sequence, ping) = replies.next_async().await.unwrap().unwrap();
                        assert_eq!(sequence, 1);
                        assert_eq!(ping[0], 0);
                    }
                }
                assert!(replies.next_async().await.unwrap().is_none());
            }
        }
    }
}

#[tokio::test]
async fn change_user_charset_rejection_follows_cleanup_and_closes_before_next_command() {
    let shim = FrontierShim {
        rejected_charset: Some(60),
        ..Default::default()
    };
    let names = Arc::clone(&shim.auth_names);
    let databases = Arc::clone(&shim.changed_databases);
    let entries = Arc::clone(&shim.change_user_entries);
    let disconnects = Arc::clone(&shim.disconnects);
    let executions = Arc::clone(&shim.command_executions);
    let mut input = raw_auth_change_packet(b"raw_\xff", b"db_\xff", 60);
    input.extend(frame(&[0x0e]));
    input.extend(frame(&[0x01]));
    let mut output = Vec::new();
    run_frontier(
        shim,
        &input,
        &mut output,
        CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_PLUGIN_AUTH,
        0,
    )
    .await
    .unwrap();
    assert_eq!(*names.lock().unwrap(), [("charset", vec![], 60, None)]);
    assert!(databases.lock().unwrap().is_empty());
    let mut replies = PacketReader::new(output.as_slice());
    let (sequence, rejected) = replies.next_async().await.unwrap().unwrap();
    assert_eq!(sequence, 1);
    assert_eq!(
        rejected.as_ref(),
        b"\xff\xcf\x04#42000actual backend charset initialization error"
    );
    assert!(replies.next_async().await.unwrap().is_none());
    assert_eq!(entries.load(Ordering::SeqCst), 1);
    assert_eq!(disconnects.load(Ordering::SeqCst), 1);
    assert_eq!(*executions.lock().unwrap(), [(0x11, false), (0x11, true)]);
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum FrontierValue {
    Null,
    Bytes(Vec<u8>, bool),
    Int(i64),
    UInt(u64),
}
struct FrontierShim {
    inner: Shim,
    values: Arc<Mutex<Vec<Vec<FrontierValue>>>>,
    changed: Arc<Mutex<Vec<CapabilityFlags>>>,
    limit: usize,
    fail_sql: bool,
    init_databases: Arc<Mutex<Vec<Vec<u8>>>>,
    init_error: bool,
    auth_names: Arc<Mutex<Vec<(&'static str, Vec<u8>, u16, Option<bool>)>>>,
    changed_databases: Arc<Mutex<Vec<(Vec<u8>, Option<Vec<u8>>, u16)>>>,
    rejected_charset: Option<u16>,
    change_user_error: bool,
    change_user_entries: Arc<AtomicUsize>,
    change_user_errors: Arc<Mutex<Vec<(u16, [u8; 5], String)>>>,
    change_user_entry_failure: bool,
    authentication_rejected: bool,
    authentication_error: Option<(u16, [u8; 5], String)>,
    command_frontiers: Arc<Mutex<Vec<(u8, bool)>>>,
    command_executions: Arc<Mutex<Vec<(u8, bool)>>>,
    query_finishes: Arc<AtomicUsize>,
    reject_command: Option<u8>,
    fail_command: Option<u8>,
    statistics_calls: Arc<AtomicUsize>,
    statistics_value_calls: Arc<AtomicUsize>,
    statistics_value: Option<StatisticsSnapshot>,
    statistics_failure: bool,
    statistics_sql_failure: bool,
    legacy_statistics_error: bool,
    wait_command: Option<u8>,
    command_gate_entered: Arc<tokio::sync::Notify>,
    command_gate_release: Arc<tokio::sync::Notify>,
    read_calls: Arc<AtomicUsize>,
    read_prior_commands: Arc<Mutex<Vec<usize>>>,
    read_reject_at: Option<usize>,
    read_fail_at: Option<usize>,
    read_error_code: u16,
    initialization_error: bool,
    initialization_calls: Arc<AtomicUsize>,
    disconnects: Arc<AtomicUsize>,
}
impl Default for FrontierShim {
    fn default() -> Self {
        Self {
            inner: Shim::default(),
            values: Arc::new(Mutex::new(Vec::new())),
            changed: Arc::new(Mutex::new(Vec::new())),
            limit: 1024,
            fail_sql: false,
            init_databases: Arc::new(Mutex::new(Vec::new())),
            init_error: false,
            auth_names: Arc::new(Mutex::new(Vec::new())),
            changed_databases: Arc::new(Mutex::new(Vec::new())),
            rejected_charset: None,
            change_user_error: false,
            change_user_entries: Arc::new(AtomicUsize::new(0)),
            change_user_errors: Arc::new(Mutex::new(Vec::new())),
            change_user_entry_failure: false,
            authentication_rejected: false,
            authentication_error: None,
            command_frontiers: Arc::new(Mutex::new(Vec::new())),
            command_executions: Arc::new(Mutex::new(Vec::new())),
            query_finishes: Arc::new(AtomicUsize::new(0)),
            reject_command: None,
            fail_command: None,
            statistics_calls: Arc::new(AtomicUsize::new(0)),
            statistics_value_calls: Arc::new(AtomicUsize::new(0)),
            statistics_value: None,
            statistics_failure: false,
            statistics_sql_failure: false,
            legacy_statistics_error: false,
            wait_command: None,
            command_gate_entered: Arc::new(tokio::sync::Notify::new()),
            command_gate_release: Arc::new(tokio::sync::Notify::new()),
            read_calls: Arc::new(AtomicUsize::new(0)),
            read_prior_commands: Arc::new(Mutex::new(Vec::new())),
            read_reject_at: None,
            read_fail_at: None,
            read_error_code: 4082,
            initialization_error: false,
            initialization_calls: Arc::new(AtomicUsize::new(0)),
            disconnects: Arc::new(AtomicUsize::new(0)),
        }
    }
}
impl FrontierShim {
    async fn execute_bound<'a, W: AsyncWrite + Unpin + Send>(
        &mut self,
        mut bindings: ParsedBindings<'a>,
        results: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        let parameters = match bindings.bind_placeholders() {
            Ok(parameters) => parameters,
            Err(error) => {
                return match error.error_kind() {
                    Some(kind) => results.error(kind, error.message()).await,
                    None => Err(error.into_io()),
                };
            }
        };
        self.values.lock().unwrap().push(
            parameters
                .iter()
                .map(|value| match value.value.into_inner() {
                    ValueInner::NULL => FrontierValue::Null,
                    ValueInner::Bytes(bytes) => {
                        FrontierValue::Bytes(bytes.to_vec(), value.is_long_data)
                    }
                    ValueInner::Int(value) => FrontierValue::Int(value),
                    ValueInner::UInt(value) => FrontierValue::UInt(value),
                    other => panic!("unexpected source value {other:?}"),
                })
                .collect(),
        );
        if self.fail_sql {
            results
                .error(crate::ErrorKind::ER_DUP_ENTRY, b"actual backend SQL error")
                .await
        } else {
            results.completed(OkResponse::default()).await
        }
    }
}
#[async_trait]
impl<W: AsyncWrite + Unpin + Send> AsyncMysqlShim<W> for FrontierShim {
    type Error = io::Error;
    fn client_collation_error(
        &self,
        charset: u16,
        _: &str,
        _: &str,
    ) -> Option<(crate::ErrorKind, String)> {
        self.auth_names
            .lock()
            .unwrap()
            .push(("charset", vec![], charset, None));
        (self.rejected_charset == Some(charset)).then(|| {
            (
                crate::ErrorKind::ER_WRONG_VALUE_FOR_VAR,
                "actual backend charset initialization error".into(),
            )
        })
    }
    fn on_client_collation(&mut self, charset: u16, _: &str, _: &str) -> io::Result<()> {
        self.auth_names
            .lock()
            .unwrap()
            .push(("publish_charset", vec![], charset, None));
        Ok(())
    }
    async fn auth_plugin_for_username(
        &self,
        username: &[u8],
        charset: u16,
        initial_handshake: bool,
    ) -> &'static str {
        self.auth_names.lock().unwrap().push((
            "plugin",
            username.to_vec(),
            charset,
            Some(initial_handshake),
        ));
        "mysql_native_password"
    }
    async fn authenticate(
        &self,
        plugin: &str,
        username: &[u8],
        charset: u16,
        initial_handshake: bool,
        salt: &[u8],
        auth_data: &[u8],
    ) -> bool {
        self.auth_names.lock().unwrap().push((
            "proof",
            username.to_vec(),
            charset,
            Some(initial_handshake),
        ));
        <Shim as AsyncMysqlShim<W>>::authenticate(
            &self.inner,
            plugin,
            username,
            charset,
            initial_handshake,
            salt,
            auth_data,
        )
        .await
    }
    async fn on_authentication_result(
        &mut self,
        username: &[u8],
        charset: u16,
        initial_handshake: bool,
        valid: bool,
    ) -> bool {
        self.auth_names.lock().unwrap().push((
            "result",
            username.to_vec(),
            charset,
            Some(initial_handshake),
        ));
        valid && !self.authentication_rejected
    }
    fn on_authenticated_user(&mut self, username: &[u8], charset: u16, initial_handshake: bool) {
        self.auth_names.lock().unwrap().push((
            "authenticated",
            username.to_vec(),
            charset,
            Some(initial_handshake),
        ));
    }
    async fn authenticated_user_admission_error(
        &mut self,
        username: &[u8],
        charset: u16,
        initial_handshake: bool,
    ) -> Option<(crate::ErrorKind, String)> {
        self.auth_names.lock().unwrap().push((
            "admission",
            username.to_vec(),
            charset,
            Some(initial_handshake),
        ));
        None
    }
    fn authentication_error_response(&self) -> Option<(u16, [u8; 5], String)> {
        self.authentication_error.clone()
    }
    fn on_change_user_error(&mut self, code: u16, state: [u8; 5], message: &str) {
        self.change_user_errors
            .lock()
            .unwrap()
            .push((code, state, message.into()));
    }
    async fn on_change_user_begin(&mut self) -> io::Result<Option<(u16, [u8; 5], String)>> {
        self.change_user_entries.fetch_add(1, Ordering::SeqCst);
        if self.change_user_entry_failure {
            Err(io::Error::other("actual CHANGE_USER cleanup failure"))
        } else {
            Ok(None)
        }
    }
    async fn on_change_user(
        &mut self,
        username: &[u8],
        database: Option<&[u8]>,
        charset: u16,
    ) -> io::Result<Option<(crate::ErrorKind, String)>> {
        self.changed_databases.lock().unwrap().push((
            username.to_vec(),
            database.map(<[u8]>::to_vec),
            charset,
        ));
        Ok(self.change_user_error.then(|| {
            (
                crate::ErrorKind::ER_BAD_DB_ERROR,
                "actual backend candidate database admission error".into(),
            )
        }))
    }
    async fn before_command_read(&mut self) -> io::Result<Option<(u16, [u8; 5], String)>> {
        let call = self.read_calls.fetch_add(1, Ordering::SeqCst) + 1;
        self.read_prior_commands
            .lock()
            .unwrap()
            .push(self.command_frontiers.lock().unwrap().len());
        if self.read_fail_at == Some(call) {
            return Err(io::Error::other("actual read-admission operational error"));
        }
        Ok((self.read_reject_at == Some(call)).then(|| {
            (
                self.read_error_code,
                *b"HY000",
                "backend quota limit=7, memory=8; 原始条件".to_owned(),
            )
        }))
    }
    async fn initialize_connection(&mut self) -> Option<(crate::ErrorKind, String)> {
        self.initialization_calls.fetch_add(1, Ordering::SeqCst);
        self.initialization_error.then(|| {
            (
                crate::ErrorKind::ER_UNKNOWN_ERROR,
                "original init-connect condition".to_owned(),
            )
        })
    }
    async fn on_disconnect(&mut self) -> io::Result<()> {
        self.disconnects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn on_init<'a>(
        &'a mut self,
        schema: &'a [u8],
        writer: InitWriter<'a, W>,
    ) -> io::Result<()> {
        self.init_databases.lock().unwrap().push(schema.to_vec());
        if self.init_error {
            writer
                .error(
                    crate::ErrorKind::ER_BAD_DB_ERROR,
                    b"actual backend database selection error",
                )
                .await
        } else {
            writer.ok().await
        }
    }
    async fn on_initial_database<'a>(
        &'a mut self,
        database: &'a [u8],
        writer: InitWriter<'a, W>,
    ) -> io::Result<bool> {
        let admitted = !self.init_error;
        <Self as AsyncMysqlShim<W>>::on_init(self, database, writer).await?;
        Ok(admitted)
    }
    fn on_command_received(&mut self, opcode: u8) -> io::Result<()> {
        self.command_frontiers.lock().unwrap().push((opcode, false));
        Ok(())
    }
    async fn on_command_begin(&mut self, opcode: u8) -> io::Result<()> {
        self.command_executions
            .lock()
            .unwrap()
            .push((opcode, false));
        Ok(())
    }
    fn on_command_finished(&mut self, opcode: u8) -> io::Result<()> {
        self.command_executions.lock().unwrap().push((opcode, true));
        Ok(())
    }
    async fn on_query_finished(&mut self) -> io::Result<()> {
        self.query_finishes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn command_admission_error(
        &mut self,
        opcode: u8,
    ) -> io::Result<Option<(crate::ErrorKind, String)>> {
        self.command_frontiers.lock().unwrap().push((opcode, true));
        if self.wait_command == Some(opcode) {
            self.command_gate_entered.notify_one();
            self.command_gate_release.notified().await;
        }
        if self.fail_command == Some(opcode) {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "actual command admission failure",
            ));
        }
        Ok((self.reject_command == Some(opcode)).then(|| {
            (
                crate::ErrorKind::ER_SPECIFIC_ACCESS_DENIED_ERROR,
                "actual backend command rejection".to_owned(),
            )
        }))
    }
    fn max_allowed_packet(&self) -> usize {
        self.limit
    }
    async fn statistics_command_error(&mut self) -> Option<(crate::ErrorKind, String)> {
        self.statistics_calls.fetch_add(1, Ordering::SeqCst);
        self.legacy_statistics_error.then(|| {
            (
                crate::ErrorKind::ER_UNKNOWN_ERROR,
                "legacy external statistics condition".to_owned(),
            )
        })
    }
    async fn on_statistics<'a>(&'a mut self, writer: StatisticsWriter<'a, W>) -> io::Result<()> {
        self.statistics_value_calls.fetch_add(1, Ordering::SeqCst);
        if self.statistics_failure {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "actual backend statistics admission failure",
            ));
        }
        if self.statistics_sql_failure {
            return writer
                .error_raw(1820, b"HY000", b"actual password expiry")
                .await;
        }
        match self.statistics_value {
            Some(facts) => writer.write(facts).await,
            None => {
                writer
                    .error(
                        crate::ErrorKind::ER_NOT_SUPPORTED_YET,
                        b"COM_STATISTICS global producers are not installed",
                    )
                    .await
            }
        }
    }
    fn status_flags(&self) -> crate::StatusFlags {
        crate::StatusFlags::SERVER_STATUS_AUTOCOMMIT | crate::StatusFlags::SERVER_STATUS_IN_TRANS
    }
    fn on_client_capabilities_changed(&mut self, flags: CapabilityFlags) {
        self.changed.lock().unwrap().push(flags);
    }
    fn query_attributes_admission(&self) -> Option<CommandAllocationAdmission> {
        <Shim as AsyncMysqlShim<W>>::query_attributes_admission(&self.inner)
    }
    async fn on_prepare<'a>(
        &'a mut self,
        sql: &'a [u8],
        writer: StatementMetaWriter<'a, W>,
    ) -> io::Result<()> {
        <Shim as AsyncMysqlShim<W>>::on_prepare(&mut self.inner, sql, writer).await
    }
    async fn on_execute<'a>(
        &'a mut self,
        _: u32,
        params: ParamParser<'a>,
        writer: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        let bindings = match params.parse_bindings() {
            Ok(bindings) => bindings,
            Err(error) => {
                return match error.error_kind() {
                    Some(kind) => writer.error(kind, error.message()).await,
                    None => Err(error.into_io()),
                };
            }
        };
        self.execute_bound(bindings, writer).await
    }
    async fn on_execute_bindings<'a>(
        &'a mut self,
        _: u32,
        bindings: ParsedBindings<'a>,
        writer: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        self.execute_bound(bindings, writer).await
    }
    async fn on_close<'a>(&'a mut self, _: u32) {}
    async fn on_query<'a>(
        &'a mut self,
        sql: &'a [u8],
        writer: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        <Shim as AsyncMysqlShim<W>>::on_query(&mut self.inner, sql, writer).await
    }
}
fn long_data(id: u32, ordinal: u16, bytes: &[u8]) -> Vec<u8> {
    let mut command = vec![0x18];
    command.extend_from_slice(&id.to_le_bytes());
    command.extend_from_slice(&ordinal.to_le_bytes());
    command.extend_from_slice(bytes);
    frame(&command)
}
async fn run_frontier(
    shim: FrontierShim,
    input: &[u8],
    output: &mut Vec<u8>,
    capabilities: CapabilityFlags,
    compression: u8,
) -> io::Result<()> {
    let mut reader = PacketReader::new(input);
    let mut writer = PacketWriter::new(output);
    match compression {
        0 => {}
        1 => {
            reader.enable_compression();
            writer.enable_compression();
        }
        2 => {
            reader.enable_zstd_compression();
            writer.enable_zstd_compression(1);
        }
        _ => panic!("invalid test transport"),
    }
    let intermediary = AsyncMysqlIntermediary {
        client_capabilities: capabilities,
        process_use_statement_on_query: false,
        reject_connection_on_dbname_absence: false,
        shim,
        reader,
        writer,
        zstd_compression_level: if compression == 2 { 1 } else { 0 },
        secure_transport: false,
    };
    intermediary.run().await
}

#[tokio::test]
async fn change_user_auth_first_error_flushes_once_and_never_dispatches_buffered_successors() {
    for first in [
        None,
        Some((3999, *b"45001", "actual first error 原因".to_owned())),
    ] {
        for fail_flush in [false, true] {
            let shim = FrontierShim {
                authentication_rejected: true,
                authentication_error: first.clone(),
                ..Default::default()
            };
            let entries = Arc::clone(&shim.change_user_entries);
            let disconnects = Arc::clone(&shim.disconnects);
            let executions = Arc::clone(&shim.command_executions);
            let databases = Arc::clone(&shim.changed_databases);
            let errors = Arc::clone(&shim.change_user_errors);
            let flushes = Arc::new(AtomicUsize::new(0));
            let mut input = raw_auth_change_packet(b"first_error", b"defaultdb", 45);
            input.extend(frame(b"\x0e"));
            input.extend(frame(b"\x03SELECT must_not_execute"));
            input.extend(frame(b"\x1c\x01\0\0\0\x01\0\0\0"));
            input.extend(frame(b"\x01"));
            let mut output = Vec::new();
            let intermediary = AsyncMysqlIntermediary {
                client_capabilities: CapabilityFlags::CLIENT_PROTOCOL_41
                    | CapabilityFlags::CLIENT_PLUGIN_AUTH,
                process_use_statement_on_query: false,
                reject_connection_on_dbname_absence: false,
                shim,
                reader: PacketReader::new(input.as_slice()),
                writer: PacketWriter::new(CommandWriteProbe {
                    output: &mut output,
                    flushes: Arc::clone(&flushes),
                    fail_flush,
                }),
                zstd_compression_level: 0,
                secure_transport: false,
            };
            let result = intermediary.run().await;
            assert_eq!(
                errors.lock().unwrap().len(),
                usize::from(first.is_none()),
                "an already published authenticator error is not issued twice"
            );
            if fail_flush {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "actual frontier flush failure"
                );
            } else {
                result.unwrap();
            }
            assert_eq!(flushes.load(Ordering::SeqCst), 1);
            assert_eq!(entries.load(Ordering::SeqCst), 1);
            assert_eq!(disconnects.load(Ordering::SeqCst), 1);
            assert!(databases.lock().unwrap().is_empty());
            assert_eq!(*executions.lock().unwrap(), [(0x11, false), (0x11, true)]);
            let mut replies = PacketReader::new(output.as_slice());
            let (sequence, response) = replies.next_async().await.unwrap().unwrap();
            assert_eq!(sequence, 1);
            let mut expected = vec![0xff];
            match &first {
                Some((code, state, message)) => {
                    expected.extend(code.to_le_bytes());
                    expected.push(b'#');
                    expected.extend(state);
                    expected.extend(message.as_bytes());
                }
                None => {
                    expected.extend(
                        (crate::ErrorKind::ER_ACCESS_DENIED_CHANGE_USER_ERROR as u16).to_le_bytes(),
                    );
                    expected
                        .extend(b"#28000Access denied for user 'first_error' (using password: NO)");
                }
            }
            assert_eq!(response.as_ref(), expected.as_slice());
            assert!(replies.next_async().await.unwrap().is_none());
        }
    }
}

#[tokio::test]
async fn change_user_cleanup_operational_error_is_not_a_sql_err_or_an_auth_attempt() {
    let shim = FrontierShim {
        change_user_entry_failure: true,
        ..Default::default()
    };
    let entries = Arc::clone(&shim.change_user_entries);
    let names = Arc::clone(&shim.auth_names);
    let executions = Arc::clone(&shim.command_executions);
    let disconnects = Arc::clone(&shim.disconnects);
    let mut input = raw_auth_change_packet(b"cleanup_io", b"defaultdb", 45);
    input.extend(frame(b"\x0e"));
    let mut output = Vec::new();
    let error = run_frontier(
        shim,
        &input,
        &mut output,
        CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_PLUGIN_AUTH,
        0,
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "actual CHANGE_USER cleanup failure");
    assert!(output.is_empty());
    assert!(names.lock().unwrap().is_empty());
    assert_eq!(*executions.lock().unwrap(), [(0x11, false)]);
    assert_eq!(entries.load(Ordering::SeqCst), 1);
    assert_eq!(disconnects.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn change_user_native_field_and_attribute_failure_phases_close_after_exact_err() {
    use super::packet_reader::compression_frame;
    let cases: Vec<(Vec<u8>, CapabilityFlags, u16, &[u8; 5], &[u8])> = vec![
        (
            b"\x11".to_vec(),
            CapabilityFlags::CLIENT_PROTOCOL_41,
            1047,
            b"08S01",
            b"Unknown command",
        ),
        (
            b"\x11no_terminator".to_vec(),
            CapabilityFlags::CLIENT_PROTOCOL_41,
            1047,
            b"08S01",
            b"Unknown command",
        ),
        (
            b"\x11user\0".to_vec(),
            CapabilityFlags::CLIENT_PROTOCOL_41,
            1047,
            b"08S01",
            b"Unknown command",
        ),
        (
            b"\x11user\0\x04x".to_vec(),
            CapabilityFlags::CLIENT_PROTOCOL_41,
            1047,
            b"08S01",
            b"Unknown command",
        ),
        (
            b"\x11user\0\0".to_vec(),
            CapabilityFlags::CLIENT_PROTOCOL_41,
            1047,
            b"08S01",
            b"Unknown command",
        ),
        (
            b"\x11user\0\0db\0\x2d\0\x05x".to_vec(),
            CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_CONNECT_ATTRS,
            1873,
            b"28000",
            b"Access denied for user '' (using password: NO)",
        ),
    ];
    for (payload, capabilities, code, state, message) in cases {
        for compression in 0..=2 {
            let shim = FrontierShim::default();
            let entries = Arc::clone(&shim.change_user_entries);
            let disconnects = Arc::clone(&shim.disconnects);
            let names = Arc::clone(&shim.auth_names);
            let executions = Arc::clone(&shim.command_executions);
            let errors = Arc::clone(&shim.change_user_errors);
            let mut input = Vec::new();
            for bytes in [
                frame(&payload),
                frame(b"\x0e"),
                frame(b"\x03SELECT hidden"),
                frame(b"\x01"),
            ] {
                input.extend(if compression == 0 {
                    bytes
                } else {
                    compression_frame(0, &bytes, compression == 2)
                });
            }
            let mut output = Vec::new();
            run_frontier(shim, &input, &mut output, capabilities, compression)
                .await
                .unwrap();
            assert_eq!(entries.load(Ordering::SeqCst), 1);
            assert_eq!(disconnects.load(Ordering::SeqCst), 1);
            assert_eq!(
                &*errors.lock().unwrap(),
                &[(code, *state, String::from_utf8(message.to_vec()).unwrap())]
            );
            assert!(
                names.lock().unwrap().is_empty(),
                "cleanup ran but authentication did not"
            );
            assert_eq!(*executions.lock().unwrap(), [(0x11, false), (0x11, true)]);
            let mut replies = PacketReader::new(output.as_slice());
            if compression == 1 {
                replies.enable_compression();
            } else if compression == 2 {
                replies.enable_zstd_compression();
            }
            let (sequence, response) = replies.next_async().await.unwrap().unwrap();
            let mut expected = vec![0xff];
            expected.extend(code.to_le_bytes());
            expected.push(b'#');
            expected.extend(state);
            expected.extend(message);
            assert_eq!(sequence, 1);
            assert_eq!(response.as_ref(), expected.as_slice());
            assert!(replies.next_async().await.unwrap().is_none());
        }
    }
}

#[tokio::test]
async fn non_entered_command_error_keeps_its_original_recoverable_dispatch() {
    for rejected_opcode in [None, Some(0x11)] {
        let shim = FrontierShim {
            reject_command: rejected_opcode,
            ..Default::default()
        };
        let entries = Arc::clone(&shim.change_user_entries);
        let names = Arc::clone(&shim.auth_names);
        let executions = Arc::clone(&shim.command_executions);
        let errors = Arc::clone(&shim.change_user_errors);
        let mut input = match rejected_opcode {
            Some(_) => raw_auth_change_packet(b"not_entered", b"defaultdb", 45),
            None => frame(b"\xfe"),
        };
        input.extend(frame(b"\x0e"));
        input.extend(frame(b"\x01"));
        let mut output = Vec::new();
        run_frontier(
            shim,
            &input,
            &mut output,
            CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_PLUGIN_AUTH,
            0,
        )
        .await
        .unwrap();
        assert_eq!(entries.load(Ordering::SeqCst), 0);
        assert!(errors.lock().unwrap().is_empty());
        assert!(names.lock().unwrap().is_empty());
        let opcode = rejected_opcode.unwrap_or(0xfe);
        assert_eq!(
            *executions.lock().unwrap(),
            [
                (opcode, false),
                (opcode, true),
                (0x0e, false),
                (0x0e, true),
                (0x01, false),
                (0x01, true)
            ]
        );
        let mut replies = PacketReader::new(output.as_slice());
        let (sequence, error) = replies.next_async().await.unwrap().unwrap();
        assert_eq!(sequence, 1);
        assert_eq!(error[0], 0xff);
        let (sequence, ping) = replies.next_async().await.unwrap().unwrap();
        assert_eq!(sequence, 1);
        assert_eq!(ping[0], 0);
        assert!(replies.next_async().await.unwrap().is_none());
    }
}

const PRECHECK_ERROR: &[u8] = b"\xff\xba\x04#HY000Incorrect arguments to mysql_stmt_precheck";

struct CommandReadProbe<'a> {
    input: &'a [u8],
    consumed: Arc<AtomicUsize>,
    polls: Arc<AtomicUsize>,
}
impl tokio::io::AsyncRead for CommandReadProbe<'_> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        // A genuine fragmented transport cannot read ahead into the next
        // command. The probe counts actual transferred bytes, not SQL calls.
        let length = self.input.len().min(buffer.remaining()).min(1);
        buffer.put_slice(&self.input[..length]);
        self.input = &self.input[length..];
        self.consumed.fetch_add(length, Ordering::SeqCst);
        std::task::Poll::Ready(Ok(()))
    }
}
struct CommandWriteProbe<'a> {
    output: &'a mut Vec<u8>,
    flushes: Arc<AtomicUsize>,
    fail_flush: bool,
}
impl AsyncWrite for CommandWriteProbe<'_> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        self.output.extend_from_slice(bytes);
        std::task::Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.flushes.fetch_add(1, Ordering::SeqCst);
        std::task::Poll::Ready(if self.fail_flush {
            Err(io::Error::other("actual frontier flush failure"))
        } else {
            Ok(())
        })
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn read_admission_is_before_payload_and_retains_native_error_exchange_sequences() {
    use super::packet_reader::compression_frame;
    for compression in 0..=2 {
        for prior_command in [false, true] {
            for code in [4081, 4082] {
                let shim = FrontierShim {
                    read_reject_at: Some(if prior_command { 2 } else { 1 }),
                    read_error_code: code,
                    ..Default::default()
                };
                let calls = Arc::clone(&shim.read_calls);
                let disconnects = Arc::clone(&shim.disconnects);
                let frontiers = Arc::clone(&shim.command_frontiers);
                let executions = Arc::clone(&shim.command_executions);
                let queries = Arc::clone(&shim.inner.query);
                let init = Arc::clone(&shim.init_databases);
                let finishes = Arc::clone(&shim.query_finishes);
                let wire_frame = |packet: Vec<u8>| {
                    if compression == 0 {
                        packet
                    } else {
                        compression_frame(0, &packet, compression == 2)
                    }
                };
                let first = wire_frame(frame(&[0x0e]));
                let rejected = wire_frame(frame(b"\x02\xff\0\xbf\\unread-schema"));
                let mut input = Vec::new();
                if prior_command {
                    input.extend_from_slice(&first);
                }
                input.extend_from_slice(&rejected);
                input.extend_from_slice(&wire_frame(frame(b"\x03SELECT unread_tail")));
                let consumed = Arc::new(AtomicUsize::new(0));
                let polls = Arc::new(AtomicUsize::new(0));
                let flushes = Arc::new(AtomicUsize::new(0));
                let mut output = Vec::new();
                let mut reader = PacketReader::new(CommandReadProbe {
                    input: &input,
                    consumed: Arc::clone(&consumed),
                    polls: Arc::clone(&polls),
                });
                let mut writer = PacketWriter::new(CommandWriteProbe {
                    output: &mut output,
                    flushes: Arc::clone(&flushes),
                    fail_flush: false,
                });
                if compression == 1 {
                    reader.enable_compression();
                    writer.enable_compression();
                } else if compression == 2 {
                    reader.enable_zstd_compression();
                    writer.enable_zstd_compression(1);
                }
                let intermediary = AsyncMysqlIntermediary {
                    client_capabilities: CapabilityFlags::CLIENT_PROTOCOL_41,
                    process_use_statement_on_query: false,
                    reject_connection_on_dbname_absence: false,
                    shim,
                    reader,
                    writer,
                    zstd_compression_level: if compression == 2 { 1 } else { 0 },
                    secure_transport: false,
                };
                intermediary.run().await.unwrap();
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    if prior_command { 2 } else { 1 }
                );
                assert_eq!(disconnects.load(Ordering::SeqCst), 1);
                assert_eq!(
                    consumed.load(Ordering::SeqCst),
                    if prior_command { first.len() } else { 0 }
                );
                if !prior_command {
                    assert_eq!(polls.load(Ordering::SeqCst), 0);
                }
                assert!(flushes.load(Ordering::SeqCst) >= 1);
                assert!(queries.lock().unwrap().is_empty());
                assert!(init.lock().unwrap().is_empty());
                assert_eq!(finishes.load(Ordering::SeqCst), 0);
                assert_eq!(
                    frontiers.lock().unwrap().as_slice(),
                    if prior_command {
                        &[(0x0e, false)][..]
                    } else {
                        &[]
                    }
                );
                assert_eq!(
                    executions.lock().unwrap().as_slice(),
                    if prior_command {
                        &[(0x0e, false), (0x0e, true)][..]
                    } else {
                        &[]
                    }
                );
                let mut replies = PacketReader::new(output.as_slice());
                if compression == 1 {
                    replies.enable_compression();
                } else if compression == 2 {
                    replies.enable_zstd_compression();
                }
                if prior_command {
                    if compression != 0 {
                        replies.set_compressed_sequence(1);
                    }
                    let (seq, ok) = replies.next_async().await.unwrap().unwrap();
                    assert_eq!(seq, 1);
                    assert_eq!(ok[0], 0);
                    if compression != 0 {
                        assert_eq!(replies.compressed_sequence(), 2);
                    }
                }
                let (seq, error) = replies.next_async().await.unwrap().unwrap();
                assert_eq!(seq, 0, "no request packet was read in this exchange");
                let mut expected = vec![0xff];
                expected.extend_from_slice(&code.to_le_bytes());
                expected.extend_from_slice(b"#HY000backend quota limit=7, memory=8; ");
                expected.extend_from_slice("原始条件".as_bytes());
                assert_eq!(error.as_ref(), expected.as_slice());
                assert!(replies.next_async().await.unwrap().is_none());
            }
        }
    }
}

#[tokio::test]
async fn read_admission_operational_or_flush_failure_closes_once_without_replaying_sql() {
    for fail_flush in [false, true] {
        let shim = FrontierShim {
            read_fail_at: (!fail_flush).then_some(1),
            read_reject_at: fail_flush.then_some(1),
            ..Default::default()
        };
        let disconnects = Arc::clone(&shim.disconnects);
        let calls = Arc::clone(&shim.read_calls);
        let commands = Arc::clone(&shim.command_frontiers);
        let consumed = Arc::new(AtomicUsize::new(0));
        let polls = Arc::new(AtomicUsize::new(0));
        let flushes = Arc::new(AtomicUsize::new(0));
        let input = frame(b"\x03SELECT unread");
        let mut output = Vec::new();
        let intermediary = AsyncMysqlIntermediary {
            client_capabilities: CapabilityFlags::CLIENT_PROTOCOL_41,
            process_use_statement_on_query: false,
            reject_connection_on_dbname_absence: false,
            shim,
            reader: PacketReader::new(CommandReadProbe {
                input: &input,
                consumed: Arc::clone(&consumed),
                polls: Arc::clone(&polls),
            }),
            writer: PacketWriter::new(CommandWriteProbe {
                output: &mut output,
                flushes: Arc::clone(&flushes),
                fail_flush,
            }),
            zstd_compression_level: 0,
            secure_transport: false,
        };
        let error = intermediary.run().await.unwrap_err();
        assert_eq!(
            error.to_string(),
            if fail_flush {
                "actual frontier flush failure"
            } else {
                "actual read-admission operational error"
            }
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(disconnects.load(Ordering::SeqCst), 1);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(consumed.load(Ordering::SeqCst), 0);
        assert!(commands.lock().unwrap().is_empty());
        if fail_flush {
            assert_eq!(flushes.load(Ordering::SeqCst), 1);
            assert_eq!(output[3], 0);
        } else {
            assert!(output.is_empty());
            assert_eq!(flushes.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn init_connect_error_keeps_original_read_boundary_without_read_error_replacement() {
    let shim = FrontierShim {
        initialization_error: true,
        read_reject_at: Some(1),
        ..Default::default()
    };
    let calls = Arc::clone(&shim.read_calls);
    let disconnects = Arc::clone(&shim.disconnects);
    let frontiers = Arc::clone(&shim.command_frontiers);
    let input = frame(b"\x03SELECT not_dispatched");
    let mut output = Vec::new();
    let intermediary = AsyncMysqlIntermediary {
        client_capabilities: CapabilityFlags::CLIENT_PROTOCOL_41,
        process_use_statement_on_query: false,
        reject_connection_on_dbname_absence: false,
        shim,
        reader: PacketReader::new(input.as_slice()),
        writer: PacketWriter::new(&mut output),
        zstd_compression_level: 0,
        secure_transport: false,
    };
    intermediary.run().await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(disconnects.load(Ordering::SeqCst), 1);
    assert!(frontiers.lock().unwrap().is_empty());
    let mut replies = PacketReader::new(output.as_slice());
    let (seq, error) = replies.next_async().await.unwrap().unwrap();
    assert_eq!(seq, 1);
    assert_eq!(
        error.as_ref(),
        b"\xff\x51\x04#HY000original init-connect condition"
    );
    assert!(replies.next_async().await.unwrap().is_none());
}

#[tokio::test]
async fn read_admission_none_preserves_fragmented_raw_init_and_next_command_lifecycle() {
    use super::packet_reader::compression_frame;
    for compression in 0..=2 {
        let shim = FrontierShim::default();
        let calls = Arc::clone(&shim.read_calls);
        let prior = Arc::clone(&shim.read_prior_commands);
        let disconnects = Arc::clone(&shim.disconnects);
        let databases = Arc::clone(&shim.init_databases);
        let executions = Arc::clone(&shim.command_executions);
        let frames = [
            frame(b"\x02\xff\0\xbf\\raw"),
            frame(&[0x0e]),
            frame(&[0x01]),
        ];
        let input = frames
            .iter()
            .flat_map(|packet| {
                if compression == 0 {
                    packet.clone()
                } else {
                    compression_frame(0, packet, compression == 2)
                }
            })
            .collect::<Vec<_>>();
        let consumed = Arc::new(AtomicUsize::new(0));
        let polls = Arc::new(AtomicUsize::new(0));
        let flushes = Arc::new(AtomicUsize::new(0));
        let mut output = Vec::new();
        let mut reader = PacketReader::new(CommandReadProbe {
            input: &input,
            consumed: Arc::clone(&consumed),
            polls: Arc::clone(&polls),
        });
        let mut writer = PacketWriter::new(CommandWriteProbe {
            output: &mut output,
            flushes: Arc::clone(&flushes),
            fail_flush: false,
        });
        if compression == 1 {
            reader.enable_compression();
            writer.enable_compression();
        } else if compression == 2 {
            reader.enable_zstd_compression();
            writer.enable_zstd_compression(1);
        }
        let intermediary = AsyncMysqlIntermediary {
            client_capabilities: CapabilityFlags::CLIENT_PROTOCOL_41,
            process_use_statement_on_query: false,
            reject_connection_on_dbname_absence: false,
            shim,
            reader,
            writer,
            zstd_compression_level: if compression == 2 { 1 } else { 0 },
            secure_transport: false,
        };
        intermediary.run().await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(prior.lock().unwrap().as_slice(), &[0, 1, 2]);
        assert_eq!(consumed.load(Ordering::SeqCst), input.len());
        assert!(polls.load(Ordering::SeqCst) >= input.len());
        assert_eq!(disconnects.load(Ordering::SeqCst), 1);
        assert_eq!(
            databases.lock().unwrap().as_slice(),
            &[b"\xff\0\xbf\\raw".to_vec()]
        );
        assert_eq!(
            executions.lock().unwrap().as_slice(),
            &[
                (0x02, false),
                (0x02, true),
                (0x0e, false),
                (0x0e, true),
                (0x01, false),
                (0x01, true)
            ]
        );
        let mut replies = PacketReader::new(output.as_slice());
        if compression == 1 {
            replies.enable_compression();
        } else if compression == 2 {
            replies.enable_zstd_compression();
        }
        for _ in 0..2 {
            if compression != 0 {
                replies.set_compressed_sequence(1);
            }
            let (sequence, ok) = replies.next_async().await.unwrap().unwrap();
            assert_eq!(sequence, 1);
            assert_eq!(ok[0], 0);
        }
        assert!(replies.next_async().await.unwrap().is_none());
    }
}

#[tokio::test]
async fn external_shim_default_read_admission_keeps_actual_query_dispatch() {
    // Shim deliberately does not implement the new callback. Exercise its
    // default through the existing packet dispatcher, not a direct hook call.
    let shim = Shim::default();
    let observed = Arc::clone(&shim.query);
    let mut input = frame(b"\x03SELECT original_default");
    input.extend_from_slice(&frame(&[0x01]));
    let mut output = Vec::new();
    run(shim, &input, &mut output, false).await.unwrap();
    assert_eq!(observed.lock().unwrap()[0].0, b"SELECT original_default");
    let mut replies = PacketReader::new(output.as_slice());
    let (sequence, ok) = replies.next_async().await.unwrap().unwrap();
    assert_eq!(sequence, 1);
    assert_eq!(ok[0], 0);
    assert!(replies.next_async().await.unwrap().is_none());
}

#[tokio::test]
async fn init_db_borrows_original_packet_bytes_and_backend_error_preserves_next_ping() {
    use super::packet_reader::compression_frame;
    let databases: &[&[u8]] = &[
        b"caf\xe9",
        b"gbk_\x81\x5c",
        "数据库".as_bytes(),
        b"\xff",
        b"db\0tail",
        b"db\xf0\x80",
        b" `database`; ",
        b"",
    ];
    for compression in 0..=2 {
        for named in [false, true] {
            for init_error in [false, true] {
                let shim = FrontierShim {
                    init_error,
                    ..Default::default()
                };
                let observed = Arc::clone(&shim.init_databases);
                let frontiers = Arc::clone(&shim.command_frontiers);
                let executions = Arc::clone(&shim.command_executions);
                let mut capabilities = CapabilityFlags::CLIENT_PROTOCOL_41;
                capabilities.set(CapabilityFlags::CLIENT_QUERY_ATTRIBUTES, named);
                let mut commands = Vec::new();
                for database in databases {
                    let mut payload = vec![0x02];
                    payload.extend_from_slice(database);
                    commands.push(frame(&payload));
                    commands.push(frame(&[0x0e]));
                }
                commands.push(frame(&[1]));
                let input: Vec<u8> = commands
                    .iter()
                    .flat_map(|command| {
                        if compression == 0 {
                            command.clone()
                        } else {
                            compression_frame(0, command, compression == 2)
                        }
                    })
                    .collect();
                let mut output = Vec::new();
                run_frontier(shim, &input, &mut output, capabilities, compression)
                    .await
                    .unwrap();
                assert_eq!(
                    *observed.lock().unwrap(),
                    databases
                        .iter()
                        .map(|bytes| bytes.to_vec())
                        .collect::<Vec<_>>()
                );
                let mut reader = PacketReader::new(output.as_slice());
                if compression == 1 {
                    reader.enable_compression();
                } else if compression == 2 {
                    reader.enable_zstd_compression();
                }
                for _ in databases {
                    let (sequence, packet) = reader.next_async().await.unwrap().unwrap();
                    assert_eq!(sequence, 1);
                    if init_error {
                        assert_eq!(
                            packet.as_ref(),
                            b"\xff\x19\x04#42000actual backend database selection error"
                        );
                    } else {
                        assert_eq!(packet.as_ref(), &[0, 0, 0, 0, 0, 0, 0]);
                    }
                    let (sequence, packet) = reader.next_async().await.unwrap().unwrap();
                    assert_eq!(sequence, 1);
                    assert_eq!(packet.as_ref(), &[0, 0, 0, 3, 0, 0, 0]);
                }
                assert!(reader.next_async().await.unwrap().is_none());
                let expected: Vec<_> = (0..databases.len())
                    .flat_map(|_| [(0x02, false), (0x02, true), (0x0e, false), (0x0e, true)])
                    .collect();
                assert_eq!(&frontiers.lock().unwrap()[..expected.len()], expected);
                assert_eq!(&executions.lock().unwrap()[..expected.len()], expected);
            }
        }
    }
}

#[tokio::test]
async fn init_db_one_byte_transport_chunks_preserve_nul_and_trailing_multibyte_boundary() {
    use tokio::io::AsyncWriteExt;
    let shim = FrontierShim::default();
    let observed = Arc::clone(&shim.init_databases);
    let database = b"\xe9\0\x81\x5c\xff";
    let mut payload = vec![0x02];
    payload.extend_from_slice(database);
    let input = [frame(&payload), frame(&[0x0e]), frame(&[1])].concat();
    let (reader, mut input_writer) = tokio::io::duplex(1);
    let mut output = Vec::new();
    let mut intermediary = AsyncMysqlIntermediary {
        client_capabilities: CapabilityFlags::CLIENT_PROTOCOL_41,
        process_use_statement_on_query: false,
        reject_connection_on_dbname_absence: false,
        shim,
        reader: PacketReader::new(reader),
        writer: PacketWriter::new(&mut output),
        zstd_compression_level: 0,
        secure_transport: false,
    };
    let producer = async {
        for byte in input {
            input_writer.write_all(&[byte]).await.unwrap();
        }
        input_writer.shutdown().await.unwrap();
    };
    let (result, ()) = tokio::join!(intermediary.run_commands(), producer);
    result.unwrap();
    drop(intermediary);
    assert_eq!(*observed.lock().unwrap(), [database.to_vec()]);
    let mut reader = PacketReader::new(output.as_slice());
    for expected in [&[0, 0, 0, 0, 0, 0, 0][..], &[0, 0, 0, 3, 0, 0, 0][..]] {
        let (sequence, packet) = reader.next_async().await.unwrap().unwrap();
        assert_eq!(sequence, 1);
        assert_eq!(packet.as_ref(), expected);
    }
    assert!(reader.next_async().await.unwrap().is_none());
}

#[tokio::test]
async fn use_compatibility_keeps_decoded_trim_contract_and_named_query_dispatch() {
    for sql in [
        b"USE  `decoded_db`; \t".as_slice(),
        b"use `decoded_db`;".as_slice(),
    ] {
        let shim = FrontierShim::default();
        let observed = Arc::clone(&shim.init_databases);
        let mut payload = vec![3];
        payload.extend_from_slice(sql);
        let input = [frame(&payload), frame(&[0x0e])].concat();
        let mut output = Vec::new();
        run_frontier(
            shim,
            &input,
            &mut output,
            CapabilityFlags::CLIENT_PROTOCOL_41,
            0,
        )
        .await
        .unwrap();
        assert_eq!(*observed.lock().unwrap(), [b"decoded_db".to_vec()]);
        assert!(errors(&output).await.is_empty());
    }
    let shim = FrontierShim::default();
    let observed = Arc::clone(&shim.init_databases);
    let mut output = Vec::new();
    let error = run_frontier(
        shim,
        &frame(b"\x03USE \xff"),
        &mut output,
        CapabilityFlags::CLIENT_PROTOCOL_41,
        0,
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(observed.lock().unwrap().is_empty());

    let shim = FrontierShim::default();
    let observed = Arc::clone(&shim.init_databases);
    let queries = Arc::clone(&shim.inner.query);
    let input = [query(b"USE db"), frame(&[0x0e])].concat();
    let mut output = Vec::new();
    run_frontier(
        shim,
        &input,
        &mut output,
        CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_QUERY_ATTRIBUTES,
        0,
    )
    .await
    .unwrap();
    assert!(observed.lock().unwrap().is_empty());
    assert_eq!(queries.lock().unwrap()[0].0, b"USE db");
}

#[test]
fn statistics_integer_rendering_preserves_native_width_wrap_and_zero_uptime() {
    // Synthetic facts test only the wire renderer, not SQL producer provenance.
    for uptime in [0, 1, 3, u64::MAX] {
        for questions in [0, 1, 2, u64::MAX / 1000, u64::MAX] {
            let facts = StatisticsSnapshot {
                uptime,
                threads: 0x8000_0000,
                questions,
                slow_queries: u64::MAX,
                opened_tables: u64::MAX,
                flush_tables: u64::MAX,
                open_tables: u32::MAX,
            };
            let qps = if uptime == 0 {
                0
            } else {
                questions.wrapping_mul(1000) / uptime
            };
            let expected = format!(
                "Uptime: {uptime}  Threads: -2147483648  Questions: {questions}  Slow queries: {}  Opens: {}  Flush tables: {}  Open tables: {}  Queries per second avg: {}.{:03}",
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u32::MAX,
                (qps / 1000) as u32,
                (qps % 1000) as u32,
            );
            let mut bytes = [0xa5; 249];
            let length = crate::format_statistics(facts, &mut bytes).unwrap();
            assert_eq!(&bytes[..length], expected.as_bytes());
            assert!(
                length <= 248,
                "native bounded stack buffer covers every field width"
            );
            assert_eq!(bytes[length], 0xa5, "no trailing NUL is sent");
        }
    }
}

#[tokio::test]
async fn statistics_is_one_text_or_error_packet_and_preserves_next_command_boundary() {
    use super::packet_reader::compression_frame;
    for compression in 0..=2 {
        for deprecated_eof in [false, true] {
            for response in 0..3 {
                let shim = FrontierShim {
                    statistics_value: (response == 0).then_some(StatisticsSnapshot {
                        uptime: 3,
                        threads: 2,
                        questions: 5,
                        slow_queries: 7,
                        opened_tables: 11,
                        flush_tables: 13,
                        open_tables: 17,
                    }),
                    statistics_sql_failure: response == 1,
                    ..Default::default()
                };
                let calls = Arc::clone(&shim.statistics_value_calls);
                let frontiers = Arc::clone(&shim.command_frontiers);
                let mut capabilities = CapabilityFlags::CLIENT_PROTOCOL_41;
                capabilities.set(CapabilityFlags::CLIENT_DEPRECATE_EOF, deprecated_eof);
                let commands = [frame(&[0x09]), frame(&[0x09]), frame(&[0x0e]), frame(&[1])];
                let input: Vec<u8> = commands
                    .iter()
                    .flat_map(|command| {
                        if compression == 0 {
                            command.clone()
                        } else {
                            compression_frame(0, command, compression == 2)
                        }
                    })
                    .collect();
                let mut output = Vec::new();
                run_frontier(shim, &input, &mut output, capabilities, compression)
                    .await
                    .unwrap();
                let mut reader = PacketReader::new(output.as_slice());
                if compression == 1 {
                    reader.enable_compression();
                }
                if compression == 2 {
                    reader.enable_zstd_compression();
                }
                let expected: &[u8] = match response {
                    0 => b"Uptime: 3  Threads: 2  Questions: 5  Slow queries: 7  Opens: 11  Flush tables: 13  Open tables: 17  Queries per second avg: 1.666",
                    1 => b"\xff\x1c\x07#HY000actual password expiry",
                    _ => b"\xff\xd3\x04#42000COM_STATISTICS global producers are not installed",
                };
                for _ in 0..2 {
                    let (sequence, packet) = reader.next_async().await.unwrap().unwrap();
                    assert_eq!(sequence, 1);
                    assert_eq!(packet.as_ref(), expected);
                }
                let (sequence, packet) = reader.next_async().await.unwrap().unwrap();
                assert_eq!(sequence, 1);
                assert_eq!(packet.as_ref(), &[0, 0, 0, 3, 0, 0, 0]);
                assert!(
                    reader.next_async().await.unwrap().is_none(),
                    "no OK/EOF after statistics"
                );
                assert_eq!(calls.load(Ordering::SeqCst), 2);
                assert_eq!(
                    &frontiers.lock().unwrap()[..4],
                    &[(0x09, false), (0x09, true), (0x09, false), (0x09, true)]
                );
            }
        }
    }
}

#[tokio::test]
async fn statistics_operational_failure_is_not_fabricated_sql_or_status_output() {
    let shim = FrontierShim {
        statistics_failure: true,
        ..Default::default()
    };
    let calls = Arc::clone(&shim.statistics_value_calls);
    let mut input = frame(&[0x09]);
    input.extend(frame(&[0x0e]));
    let mut output = Vec::new();
    let error = run_frontier(
        shim,
        &input,
        &mut output,
        CapabilityFlags::CLIENT_PROTOCOL_41,
        0,
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
    assert_eq!(
        error.to_string(),
        "actual backend statistics admission failure"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        output.is_empty(),
        "no zero-counter text, SQL ERR, OK, or next PING"
    );
}

#[tokio::test]
async fn statistics_command_admission_failure_cannot_read_backend_facts() {
    for rejected in [false, true] {
        let shim = FrontierShim {
            reject_command: rejected.then_some(0x09),
            fail_command: (!rejected).then_some(0x09),
            statistics_value: Some(StatisticsSnapshot {
                uptime: 1,
                threads: 9,
                questions: 13,
                slow_queries: 19,
                opened_tables: 23,
                flush_tables: 29,
                open_tables: 31,
            }),
            ..Default::default()
        };
        let legacy_calls = Arc::clone(&shim.statistics_calls);
        let value_calls = Arc::clone(&shim.statistics_value_calls);
        let mut input = frame(&[0x09]);
        input.extend(frame(&[0x0e]));
        input.extend(frame(&[1]));
        let mut output = Vec::new();
        let result = run_frontier(
            shim,
            &input,
            &mut output,
            CapabilityFlags::CLIENT_PROTOCOL_41,
            0,
        )
        .await;
        if rejected {
            result.unwrap();
            let mut reader = PacketReader::new(output.as_slice());
            let (sequence, packet) = reader.next_async().await.unwrap().unwrap();
            assert_eq!(sequence, 1);
            assert_eq!(
                packet.as_ref(),
                b"\xff\xcb\x04#42000actual backend command rejection"
            );
            let (sequence, ping) = reader.next_async().await.unwrap().unwrap();
            assert_eq!(sequence, 1);
            assert_eq!(ping.as_ref(), &[0, 0, 0, 3, 0, 0, 0]);
            assert!(reader.next_async().await.unwrap().is_none());
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::OutOfMemory);
            assert!(output.is_empty());
        }
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);
        assert_eq!(value_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn native_decoded_command_boundaries_cover_continue_unknown_empty_and_no_response() {
    let shim = FrontierShim::default();
    let executions = Arc::clone(&shim.command_executions);
    let frontiers = Arc::clone(&shim.command_frontiers);
    let commands = [
        frame(&[0x18, 1]),                      // malformed native fields: no dispatch
        frame(&[0xff]),                         // genuine unknown command dispatches
        frame(&[]),                             // native COM_SLEEP dispatch
        frame(&[0x1b, 2, 0]),                   // ERR + continue
        long_data(99, 0, b"unknown statement"), // no-response continue
        frame(&[0x09]),
        frame(&[0x0e]),
        frame(&[1]),
    ];
    let input: Vec<u8> = commands.into_iter().flatten().collect();
    let mut output = Vec::new();
    run_frontier(
        shim,
        &input,
        &mut output,
        CapabilityFlags::CLIENT_PROTOCOL_41,
        0,
    )
    .await
    .unwrap();
    assert_eq!(
        *executions.lock().unwrap(),
        vec![
            (0xff, false),
            (0xff, true),
            (0, false),
            (0, true),
            (0x1b, false),
            (0x1b, true),
            (0x18, false),
            (0x18, true),
            (0x09, false),
            (0x09, true),
            (0x0e, false),
            (0x0e, true),
            (1, false),
            (1, true),
        ]
    );
    let mut reader = PacketReader::new(output.as_slice());
    for kind in [1047_u16, 1047, 1047, 1047, 1235] {
        let (sequence, packet) = reader.next_async().await.unwrap().unwrap();
        assert_eq!(sequence, 1);
        assert_eq!(packet[0], 0xff);
        assert_eq!(u16::from_le_bytes([packet[1], packet[2]]), kind);
    }
    let (sequence, ping) = reader.next_async().await.unwrap().unwrap();
    assert_eq!(sequence, 1);
    assert_eq!(ping.as_ref(), &[0, 0, 0, 3, 0, 0, 0]);
    assert!(reader.next_async().await.unwrap().is_none());
    assert_eq!(
        *frontiers.lock().unwrap(),
        [0xff, 0, 0x1b, 0x18, 0x09, 0x0e, 1]
            .into_iter()
            .flat_map(|opcode| [(opcode, false), (opcode, true)])
            .collect::<Vec<_>>(),
        "empty native COM_SLEEP also uses the original admission gate once"
    );
}

#[tokio::test]
async fn existing_query_finished_is_the_only_terminal_for_sql_execute_and_sql_control_helpers() {
    let shim = FrontierShim::default();
    let executions = Arc::clone(&shim.command_executions);
    let query_finishes = Arc::clone(&shim.query_finishes);
    let values = Arc::clone(&shim.values);
    let queries = Arc::clone(&shim.inner.query);
    let mut input = frame(b"\x03SELECT actual");
    input.extend(frame(b"\x16SELECT ?"));
    input.extend(execute(
        7,
        0,
        &[0, 1, ColumnType::MYSQL_TYPE_LONG as u8, 0, 42, 0, 0, 0],
    ));
    input.extend(frame(&[0x07, 4])); // actual COM_REFRESH SQL helper
    input.extend(frame(&[0x0a])); // actual COM_PROCESS_INFO SQL helper
    input.extend(frame(&[0x0c, 3, 0, 0, 0])); // actual COM_PROCESS_KILL SQL helper
    input.extend(frame(&[1]));
    let mut output = Vec::new();
    run_frontier(
        shim,
        &input,
        &mut output,
        CapabilityFlags::CLIENT_PROTOCOL_41,
        0,
    )
    .await
    .unwrap();
    assert_eq!(query_finishes.load(Ordering::SeqCst), 5);
    assert_eq!(
        *executions.lock().unwrap(),
        vec![
            (0x03, false),
            (0x16, false),
            (0x16, true),
            (0x17, false),
            (0x07, false),
            (0x0a, false),
            (0x0c, false),
            (1, false),
            (1, true),
        ],
        "SQL completion must not also issue the new packet terminal"
    );
    assert_eq!(*values.lock().unwrap(), vec![vec![FrontierValue::Int(42)]]);
    assert_eq!(
        *queries.lock().unwrap(),
        vec![
            (b"SELECT actual".to_vec(), vec![]),
            (b"FLUSH TABLES /* COM_REFRESH */".to_vec(), vec![]),
            (b"SHOW PROCESSLIST /* COM_PROCESS_INFO */".to_vec(), vec![]),
            (b"KILL CONNECTION 3".to_vec(), vec![]),
        ],
        "one actual callback per source, no second execution for terminal bookkeeping"
    );
    assert!(errors(&output).await.is_empty());
}

#[tokio::test]
async fn native_execute_packet_decode_precedes_ordinal_but_setter_errors_finish_original_command() {
    let shim = FrontierShim::default();
    let executions = Arc::clone(&shim.command_executions);
    let frontiers = Arc::clone(&shim.command_frontiers);
    let values = Arc::clone(&shim.values);
    let mut input = frame(b"\x16SELECT ?");
    input.extend(execute(7, 8, &[1, 0, 1, 1])); // malformed native descriptor
    input.extend(execute(7, 8, &[0])); // complete N<P: dispatch then precheck
    input.extend(execute(7, 8, &[1, 1, 1, 1, 1, 0])); // invalid setter type
    input.extend(frame(&[1]));
    let mut output = Vec::new();
    run_frontier(
        shim,
        &input,
        &mut output,
        CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_QUERY_ATTRIBUTES,
        0,
    )
    .await
    .unwrap();
    assert_eq!(
        *executions.lock().unwrap(),
        vec![
            (0x16, false),
            (0x16, true),
            (0x17, false),
            (0x17, true),
            (0x17, false),
            (0x17, true),
            (1, false),
            (1, true),
        ]
    );
    assert!(
        values.lock().unwrap().is_empty(),
        "no fake parameter VALUE after setter failure"
    );
    assert_eq!(
        *frontiers.lock().unwrap(),
        [0x16, 0x17, 0x17, 1]
            .into_iter()
            .flat_map(|opcode| [(opcode, false), (opcode, true)])
            .collect::<Vec<_>>(),
        "malformed native get_command emits neither Questions nor dispatch admission"
    );
    assert_eq!(
        errors(&output).await,
        vec![
            b"\xff\x2b\x07#HY000Malformed communication packet.".to_vec(),
            b"\xff\xba\x04#HY000Incorrect arguments to COM_STMT_EXECUTE".to_vec(),
            b"\xff\xba\x04#HY000Incorrect arguments to mysqld_stmt_execute".to_vec(),
        ]
    );
}

#[tokio::test]
async fn parsed_command_gate_precedes_mutation_and_debug_uses_negotiated_native_eof() {
    use super::packet_reader::compression_frame;
    for compression in 0..=2 {
        for deprecated in [false, true] {
            let shim = FrontierShim {
                reject_command: Some(0x1b),
                ..Default::default()
            };
            let changed = Arc::clone(&shim.changed);
            let frontiers = Arc::clone(&shim.command_frontiers);
            let queries = Arc::clone(&shim.inner.query);
            let mut capabilities = CapabilityFlags::CLIENT_PROTOCOL_41;
            capabilities.set(CapabilityFlags::CLIENT_DEPRECATE_EOF, deprecated);
            let commands = [
                frame(&[0x18, 99]), // malformed: no parsed-command admission
                frame(&[0x1b, 0, 0]),
                frame(&[0x1b, 2, 0]), // native gate precedes SET_OPTION validation
                frame(&[0x0d]),
                frame(&[0x0e]),
                frame(b"\x03SELECT actual_successor"),
                frame(&[1]),
            ];
            let input = commands
                .iter()
                .flat_map(|command| {
                    if compression == 0 {
                        command.clone()
                    } else {
                        compression_frame(0, command, compression == 2)
                    }
                })
                .collect::<Vec<_>>();
            let mut output = Vec::new();
            run_frontier(shim, &input, &mut output, capabilities, compression)
                .await
                .unwrap();
            let mut reader = PacketReader::new(output.as_slice());
            if compression == 1 {
                reader.enable_compression();
            }
            if compression == 2 {
                reader.enable_zstd_compression();
            }
            let eof: &[u8] = if deprecated {
                &[0xfe, 0, 0, 3, 0, 0, 0]
            } else {
                &[0xfe, 0, 0, 3, 0]
            };
            for expected in [
                b"\xff\x17\x04#08S01malformed command packet".as_slice(),
                b"\xff\xcb\x04#42000actual backend command rejection".as_slice(),
                b"\xff\xcb\x04#42000actual backend command rejection".as_slice(),
                eof,
                &[0, 0, 0, 3, 0, 0, 0],
            ] {
                if compression != 0 {
                    reader.set_compressed_sequence(1);
                }
                let (sequence, packet) = reader.next_async().await.unwrap().unwrap();
                assert_eq!(sequence, 1);
                assert_eq!(packet.as_ref(), expected);
            }
            if compression != 0 {
                reader.set_compressed_sequence(1);
            }
            let (sequence, packet) = reader.next_async().await.unwrap().unwrap();
            assert_eq!(sequence, 1);
            assert_eq!(packet[0], 0);
            assert!(reader.next_async().await.unwrap().is_none());
            assert!(
                changed.lock().unwrap().is_empty(),
                "rejection must not mutate capabilities"
            );
            assert_eq!(
                *queries.lock().unwrap(),
                vec![(b"SELECT actual_successor".to_vec(), vec![])]
            );
            assert_eq!(
                *frontiers.lock().unwrap(),
                [0x1b, 0x1b, 0x0d, 0x0e, 3, 1]
                    .into_iter()
                    .flat_map(|opcode| [(opcode, false), (opcode, true)])
                    .collect::<Vec<_>>(),
                "only actually parsed commands issue received then admission once"
            );
        }
    }
}

#[tokio::test]
async fn malformed_query_attributes_precede_questions_and_valid_decode_precedes_password_gate() {
    let shim = FrontierShim {
        reject_command: Some(3),
        ..Default::default()
    };
    let frontiers = Arc::clone(&shim.command_frontiers);
    let executions = Arc::clone(&shim.command_executions);
    let queries = Arc::clone(&shim.inner.query);
    let values = Arc::clone(&shim.values);
    let mut input = frame(&[3]); // negotiated native descriptor is missing
    input.extend(query(b"SELECT actual_rejected"));
    input.extend(frame(&[1]));
    let mut output = Vec::new();
    run_frontier(
        shim,
        &input,
        &mut output,
        CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_QUERY_ATTRIBUTES,
        0,
    )
    .await
    .unwrap();
    assert_eq!(
        *frontiers.lock().unwrap(),
        vec![(3, false), (3, true), (1, false), (1, true)]
    );
    assert_eq!(
        *executions.lock().unwrap(),
        vec![(3, false), (3, true), (1, false), (1, true)]
    );
    assert!(queries.lock().unwrap().is_empty());
    assert!(
        values.lock().unwrap().is_empty(),
        "admission never consumes the parameter VALUE"
    );
    assert_eq!(
        errors(&output).await,
        vec![
            b"\xff\x2b\x07#HY000Malformed communication packet.".to_vec(),
            b"\xff\xcb\x04#42000actual backend command rejection".to_vec(),
        ]
    );
}

#[tokio::test]
async fn rejected_statement_reset_close_and_connection_reset_preserve_actual_parameter_owner() {
    for rejected in [0x1a, 0x19, 0x1f] {
        let shim = FrontierShim {
            reject_command: Some(rejected),
            ..Default::default()
        };
        let values = Arc::clone(&shim.values);
        let current = Arc::clone(&shim.inner.current);
        let peak = Arc::clone(&shim.inner.peak);
        let mut input = frame(b"\x16SELECT ?");
        input.extend(execute(7, 8, &[1, 0, 1, 254, 0, 0, 1, b'a']));
        input.extend(long_data(7, 0, b"held actual long data"));
        let mut command = vec![rejected];
        if rejected != 0x1f {
            command.extend_from_slice(&7u32.to_le_bytes());
        }
        input.extend(frame(&command));
        input.extend(execute(7, 8, &[1, 0, 0]));
        input.extend(frame(&[1]));
        let mut output = Vec::new();
        run_frontier(
            shim,
            &input,
            &mut output,
            CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_QUERY_ATTRIBUTES,
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            *values.lock().unwrap(),
            vec![
                vec![FrontierValue::Bytes(b"a".to_vec(), false)],
                vec![FrontierValue::Bytes(
                    b"held actual long data".to_vec(),
                    true
                )],
            ],
            "rejected command cannot clear statement, source types or long-data owner"
        );
        assert_eq!(
            errors(&output).await,
            vec![b"\xff\xcb\x04#42000actual backend command rejection".to_vec()]
        );
        assert_eq!(
            current.load(Ordering::SeqCst),
            0,
            "last command owner releases admissions"
        );
        assert!(
            peak.load(Ordering::SeqCst) > 0,
            "actual admitted type/binding allocations"
        );
    }
}

#[tokio::test]
async fn command_gate_operational_failure_is_not_sql_error_and_drops_existing_statement_leases() {
    let shim = FrontierShim {
        fail_command: Some(0x1b),
        ..Default::default()
    };
    let changed = Arc::clone(&shim.changed);
    let frontiers = Arc::clone(&shim.command_frontiers);
    let current = Arc::clone(&shim.inner.current);
    let peak = Arc::clone(&shim.inner.peak);
    let queries = Arc::clone(&shim.inner.query);
    let mut input = frame(b"\x16SELECT ?");
    input.extend(execute(7, 8, &[1, 0, 1, 254, 0, 0, 1, b'a']));
    input.extend(long_data(7, 0, b"owned until command failure"));
    input.extend(frame(&[0x1b, 0, 0]));
    input.extend(frame(b"\x03must_not_execute"));
    let mut output = Vec::new();
    let error = run_frontier(
        shim,
        &input,
        &mut output,
        CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_QUERY_ATTRIBUTES,
        0,
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
    assert_eq!(error.to_string(), "actual command admission failure");
    assert!(
        errors(&output).await.is_empty(),
        "operational failure is not a forged SQL ERR"
    );
    assert!(changed.lock().unwrap().is_empty());
    assert!(queries.lock().unwrap().is_empty());
    assert_eq!(
        *frontiers.lock().unwrap(),
        vec![
            (0x16, false),
            (0x16, true),
            (0x17, false),
            (0x17, true),
            (0x18, false),
            (0x18, true),
            (0x1b, false),
            (0x1b, true)
        ]
    );
    assert_eq!(current.load(Ordering::SeqCst), 0);
    assert!(peak.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn external_shim_default_has_no_principal_gate_and_debug_still_uses_native_eof() {
    let shim = Shim::default(); // no command_admission_error implementation
    let mut input = frame(&[0x0d]);
    input.extend(frame(&[0x0e]));
    input.extend(frame(&[1]));
    let mut output = Vec::new();
    run(shim, &input, &mut output, false).await.unwrap();
    let mut reader = PacketReader::new(output.as_slice());
    let (sequence, debug) = reader.next_async().await.unwrap().unwrap();
    assert_eq!(sequence, 1);
    assert_eq!(debug.as_ref(), &[0xfe, 0, 0, 2, 0]);
    let (sequence, ping) = reader.next_async().await.unwrap().unwrap();
    assert_eq!(sequence, 1);
    assert_eq!(ping.as_ref(), &[0, 0, 0, 2, 0, 0, 0]);
    assert!(reader.next_async().await.unwrap().is_none());
}

#[tokio::test]
async fn rejected_debug_emits_only_err_and_legacy_statistics_hook_keeps_external_contract() {
    for opcode in [0x0d, 0x09] {
        for rejected in [false, true] {
            let shim = FrontierShim {
                reject_command: rejected.then_some(opcode),
                legacy_statistics_error: true,
                ..Default::default()
            };
            let statistics_calls = Arc::clone(&shim.statistics_calls);
            let statistics_value_calls = Arc::clone(&shim.statistics_value_calls);
            let mut input = frame(&[opcode]);
            input.extend(frame(&[0x0e]));
            input.extend(frame(&[1]));
            let mut output = Vec::new();
            run_frontier(
                shim,
                &input,
                &mut output,
                CapabilityFlags::CLIENT_PROTOCOL_41,
                0,
            )
            .await
            .unwrap();
            let mut reader = PacketReader::new(output.as_slice());
            let (sequence, packet) = reader.next_async().await.unwrap().unwrap();
            assert_eq!(sequence, 1);
            let expected: &[u8] = if rejected {
                b"\xff\xcb\x04#42000actual backend command rejection"
            } else if opcode == 0x09 {
                b"\xff\x51\x04#HY000legacy external statistics condition"
            } else {
                &[0xfe, 0, 0, 3, 0]
            };
            assert_eq!(packet.as_ref(), expected);
            let (sequence, ping) = reader.next_async().await.unwrap().unwrap();
            assert_eq!(sequence, 1);
            assert_eq!(ping.as_ref(), &[0, 0, 0, 3, 0, 0, 0]);
            assert!(
                reader.next_async().await.unwrap().is_none(),
                "no stray DEBUG EOF"
            );
            assert_eq!(
                statistics_calls.load(Ordering::SeqCst),
                usize::from(opcode == 0x09 && !rejected),
                "new gate must precede old public statistics hook, without removing it"
            );
            assert_eq!(statistics_value_calls.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn async_command_gate_keeps_original_statement_owner_until_admitted_or_abandoned() {
    for abandon in [false, true] {
        let shim = FrontierShim {
            wait_command: Some(0x1b),
            ..Default::default()
        };
        let entered = Arc::clone(&shim.command_gate_entered);
        let release = Arc::clone(&shim.command_gate_release);
        let frontiers = Arc::clone(&shim.command_frontiers);
        let changed = Arc::clone(&shim.changed);
        let values = Arc::clone(&shim.values);
        let current = Arc::clone(&shim.inner.current);
        let mut input = frame(b"\x16SELECT ?");
        input.extend(execute(7, 8, &[1, 0, 1, 254, 0, 0, 1, b'a']));
        input.extend(long_data(7, 0, b"still the original statement"));
        input.extend(frame(&[0x1b, 0, 0]));
        input.extend(frame(&[0x0e]));
        input.extend(frame(&[1]));
        let capabilities =
            CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_QUERY_ATTRIBUTES;
        let mut output = Vec::new();
        {
            let mut dispatch = Box::pin(run_frontier(shim, &input, &mut output, capabilities, 0));
            tokio::select! {
                biased;
                _ = entered.notified() => {}
                result = &mut dispatch => panic!("command gate must await original authorization: {result:?}"),
            }
            assert!(
                current.load(Ordering::SeqCst) > 0,
                "actual original type/statement admission remains held across await"
            );
            assert!(
                changed.lock().unwrap().is_empty(),
                "awaiting authorization cannot mutate SET_OPTION capabilities"
            );
            assert_eq!(
                *values.lock().unwrap(),
                vec![vec![FrontierValue::Bytes(b"a".to_vec(), false)]]
            );
            assert_eq!(
                *frontiers.lock().unwrap(),
                vec![
                    (0x16, false),
                    (0x16, true),
                    (0x17, false),
                    (0x17, true),
                    (0x18, false),
                    (0x18, true),
                    (0x1b, false),
                    (0x1b, true)
                ]
            );
            if !abandon {
                release.notify_one();
                dispatch.await.unwrap();
            }
            // Otherwise drop this actual dispatch future while the gate owns
            // its original statement map, not a synthetic callback-only future.
        }
        assert_eq!(
            current.load(Ordering::SeqCst),
            0,
            "last physical owner releases"
        );
        assert!(
            errors(&output).await.is_empty(),
            "abandoning admission cannot fabricate an SQL permission condition"
        );
        if abandon {
            assert!(changed.lock().unwrap().is_empty());
            assert_eq!(frontiers.lock().unwrap().len(), 8, "no successor command");
        } else {
            assert_eq!(
                *changed.lock().unwrap(),
                vec![capabilities | CapabilityFlags::CLIENT_MULTI_STATEMENTS]
            );
            assert_eq!(
                *frontiers.lock().unwrap(),
                vec![
                    (0x16, false),
                    (0x16, true),
                    (0x17, false),
                    (0x17, true),
                    (0x18, false),
                    (0x18, true),
                    (0x1b, false),
                    (0x1b, true),
                    (0x0e, false),
                    (0x0e, true),
                    (1, false),
                    (1, true)
                ]
            );
        }
    }
}

#[tokio::test]
async fn deferred_setter_allocation_failure_is_operational_and_releases_actual_binding_owner() {
    let shim = FrontierShim::default();
    let values = shim.values.clone();
    let mut output = Vec::new();
    let mut state = crate::StatementData {
        params: 1,
        long_data_error: Some(crate::ErrorKind::ER_UNKNOWN_ERROR),
        ..Default::default()
    };
    state.long_data.insert(0, b"borrowed".to_vec());
    let calls = Arc::new(AtomicUsize::new(0));
    let current = Arc::new(AtomicUsize::new(0));
    let admission: CommandAllocationAdmission = {
        let calls = calls.clone();
        let current = current.clone();
        Arc::new(move |bytes| {
            if calls.fetch_add(1, Ordering::SeqCst) == 1 {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "actual binding admission",
                ));
            }
            current.fetch_add(bytes, Ordering::SeqCst);
            Ok(Arc::new(Lease {
                current: current.clone(),
                bytes,
            }))
        })
    };
    {
        let mut intermediary = AsyncMysqlIntermediary {
            client_capabilities: CapabilityFlags::CLIENT_PROTOCOL_41
                | CapabilityFlags::CLIENT_QUERY_ATTRIBUTES,
            process_use_statement_on_query: false,
            reject_connection_on_dbname_absence: false,
            shim,
            reader: PacketReader::new(&[][..]),
            writer: PacketWriter::new(&mut output),
            zstd_compression_level: 0,
            secure_transport: false,
        };
        let params = bytes::Bytes::from_static(&[1, 1, 1, 254, 0, 0]);
        let error = intermediary
            .run_execute_until_disconnect(
                7,
                &params,
                &mut state,
                true,
                8,
                Some(admission),
                &mut false,
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert_eq!(error.to_string(), "actual binding admission");
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "one framing collection then actual setter collection"
    );
    assert_eq!(current.load(Ordering::SeqCst), 0);
    assert!(
        state.long_data.is_empty(),
        "actual setter failure resets values"
    );
    assert_eq!(
        state.long_data_error,
        Some(crate::ErrorKind::ER_UNKNOWN_ERROR)
    );
    assert!(values.lock().unwrap().is_empty());
    assert!(
        output.is_empty(),
        "operational OOM is not a forged1105/deferred SQL response"
    );
}

#[tokio::test]
async fn zero_parameter_sticky_error_and_connection_reset_never_reuse_old_statement_state() {
    for named in [false, true] {
        let mut shim = FrontierShim::default();
        shim.inner.parameters.clear();
        let values = shim.values.clone();
        let current = shim.inner.current.clone();
        let capabilities = CapabilityFlags::CLIENT_PROTOCOL_41
            | if named {
                CapabilityFlags::CLIENT_QUERY_ATTRIBUTES
            } else {
                CapabilityFlags::empty()
            };
        let tail: &[u8] = if named { &[0] } else { &[] };
        let flags = if named { 8 } else { 0 };
        let mut input = frame(b"\x16SELECT 1");
        input.extend(long_data(7, 0, b"no-parameter"));
        input.extend(execute(7, flags, tail));
        input.extend(execute(7, flags, tail));
        input.extend(frame(&[0x1a, 7, 0, 0, 0]));
        input.extend(execute(7, flags, tail));
        input.extend(long_data(7, 0, b"must-not-outlive-reset"));
        input.extend(frame(&[0x1f]));
        input.extend(execute(7, flags, &[255])); // reset destroyed id
        input.extend(frame(b"\x16SELECT 1"));
        input.extend(execute(7, flags, tail));
        input.extend(frame(&[1]));
        let mut output = Vec::new();
        run_frontier(shim, &input, &mut output, capabilities, 0)
            .await
            .unwrap();
        assert_eq!(errors(&output).await, vec![
            PRECHECK_ERROR.to_vec(), PRECHECK_ERROR.to_vec(),
            b"\xff\xdb\x04#HY000Unknown prepared statement handler (7) given to mysql_stmt_precheck".to_vec(),
        ]);
        assert_eq!(*values.lock().unwrap(), vec![vec![], vec![]]);
        assert_eq!(current.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn early_deferred_gate_retains_same_value_and_admission_until_actual_statement_drop() {
    let shim = FrontierShim::default();
    let current = shim.inner.current.clone();
    let admission = <FrontierShim as AsyncMysqlShim<Vec<u8>>>::query_attributes_admission(&shim);
    let values = shim.values.clone();
    let mut state = crate::StatementData {
        params: 1,
        long_data_error: Some(crate::ErrorKind::ER_WRONG_ARGUMENTS),
        ..Default::default()
    };
    state.long_data.insert(0, b"same-owner".to_vec());
    let pointer = state.long_data[&0].as_ptr();
    let mut output = Vec::new();
    {
        let mut intermediary = AsyncMysqlIntermediary {
            client_capabilities: CapabilityFlags::CLIENT_PROTOCOL_41
                | CapabilityFlags::CLIENT_QUERY_ATTRIBUTES,
            process_use_statement_on_query: false,
            reject_connection_on_dbname_absence: false,
            shim,
            reader: PacketReader::new(&[][..]),
            writer: PacketWriter::new(&mut output),
            zstd_compression_level: 0,
            secure_transport: false,
        };
        for params in [
            bytes::Bytes::from_static(&[1, 1, 1, 254, 0, 0]),
            bytes::Bytes::from_static(&[1, 1, 0]),
        ] {
            intermediary
                .run_execute_until_disconnect(
                    7,
                    &params,
                    &mut state,
                    true,
                    8,
                    admission.clone(),
                    &mut false,
                )
                .await
                .unwrap();
            assert_eq!(state.long_data[&0].as_ptr(), pointer);
            assert_eq!(state.long_data[&0], b"same-owner");
            assert_eq!(state.bound_types, vec![(254, false)]);
            assert_eq!(
                current.load(Ordering::SeqCst),
                std::mem::size_of::<(u16, bool)>(),
                "only actual saved type collection remains after temporary packet/setter leases"
            );
        }
    }
    assert!(values.lock().unwrap().is_empty());
    assert_eq!(
        errors(&output).await,
        vec![PRECHECK_ERROR.to_vec(), PRECHECK_ERROR.to_vec()]
    );
    drop(state);
    assert_eq!(current.load(Ordering::SeqCst), 0);
}

const SETTER_ERROR: &[u8] = b"\xff\xba\x04#HY000Incorrect arguments to mysqld_stmt_execute";
const LONG_DATA_ERROR: &[u8] = b"\xff\x51\x04#HY000Parameter of prepared statement which is set through mysql_send_long_data() is longer than 'max_allowed_packet' bytes";

#[tokio::test]
async fn silent_unknown_long_data_and_capability_eof_keep_actual_command_sequences() {
    use super::packet_reader::compression_frame;
    for compression in 0..=2 {
        for deprecated in [false, true] {
            let shim = FrontierShim::default();
            let changed = shim.changed.clone();
            let observed = shim.inner.query.clone();
            let mut capabilities = CapabilityFlags::CLIENT_PROTOCOL_41;
            capabilities.set(CapabilityFlags::CLIENT_DEPRECATE_EOF, deprecated);
            let commands = [
                long_data(99, 0, b"unknown-secret"),
                frame(&[0x19, 99, 0, 0, 0]),
                frame(&[0x18, 99]), // syntactically incomplete, not silent lookup
                frame(&[0x1b, 0, 0]),
                frame(&[0x1b, 1, 0]),
                frame(&[0x1b, 2, 0]),
                frame(b"\x03SELECT next_response"),
                frame(&[1]),
            ];
            let input = commands
                .iter()
                .flat_map(|command| {
                    if compression == 0 {
                        command.clone()
                    } else {
                        compression_frame(0, command, compression == 2)
                    }
                })
                .collect::<Vec<_>>();
            let mut output = Vec::new();
            run_frontier(shim, &input, &mut output, capabilities, compression)
                .await
                .unwrap();
            let mut reader = PacketReader::new(output.as_slice());
            if compression == 1 {
                reader.enable_compression();
            }
            if compression == 2 {
                reader.enable_zstd_compression();
            }
            let eof: &[u8] = if deprecated {
                &[0xfe, 0, 0, 3, 0, 0, 0]
            } else {
                &[0xfe, 0, 0, 3, 0]
            };
            for expected in [
                b"\xff\x17\x04#08S01malformed command packet".as_slice(),
                eof,
                eof,
                b"\xff\x17\x04#08S01Unknown command".as_slice(),
            ] {
                if compression != 0 {
                    reader.set_compressed_sequence(1);
                }
                let (sequence, packet) = reader.next_async().await.unwrap().unwrap();
                assert_eq!(sequence, 1);
                assert_eq!(
                    packet.as_ref(),
                    expected,
                    "no stray long-data/CLOSE response"
                );
            }
            if compression != 0 {
                reader.set_compressed_sequence(1);
            }
            let (sequence, query_ok) = reader.next_async().await.unwrap().unwrap();
            assert_eq!(sequence, 1);
            assert_eq!(query_ok[0], 0);
            assert!(reader.next_async().await.unwrap().is_none());
            assert_eq!(
                changed.lock().unwrap().as_slice(),
                &[
                    capabilities | CapabilityFlags::CLIENT_MULTI_STATEMENTS,
                    capabilities & !CapabilityFlags::CLIENT_MULTI_STATEMENTS,
                ]
            );
            assert_eq!(
                observed.lock().unwrap().as_slice(),
                &[(b"SELECT next_response".to_vec(), vec![])]
            );
        }
    }
}

#[tokio::test]
async fn native_sticky_long_data_error_survives_frame_errors_and_types_then_reset_close() {
    for named in [false, true] {
        for cursor in [false, true] {
            let shim = FrontierShim::default();
            let observed = shim.values.clone();
            let current = shim.inner.current.clone();
            let mut capabilities = CapabilityFlags::CLIENT_PROTOCOL_41;
            capabilities.set(CapabilityFlags::CLIENT_QUERY_ATTRIBUTES, named);
            let flags = if cursor { 1 } else { 0 } | if named { 8 } else { 0 };
            let tail = |body: &[u8]| {
                if named {
                    if body.len() >= 4 && body[1] != 0 {
                        [&[1][..], &body[..4], &[0][..], &body[4..]].concat()
                    } else {
                        [&[1][..], body].concat()
                    }
                } else {
                    body.to_vec()
                }
            };
            let mut input = frame(b"\x16SELECT ?");
            input.extend(long_data(7, 1, b"bad-ordinal-secret"));
            input.extend(execute(7, flags, &tail(&[0, 1, 1]))); // descriptor truncated
            input.extend(execute(7, flags, &tail(&[0, 1, 1, 0, 7]))); // saves TINY
            input.extend(execute(7, flags, &tail(&[0, 0, 8]))); // same sticky error
            input.extend(frame(&[0x1a, 7, 0, 0, 0]));
            input.extend(execute(7, flags, &tail(&[0, 0, 9]))); // RESET retains TINY
            input.extend(frame(&[0x19, 7, 0, 0, 0]));
            input.extend(long_data(7, 0, b"silent-after-close"));
            input.extend(execute(7, flags, &[255])); // lookup precedes frame error
            input.extend(frame(b"\x16SELECT ?")); // same test id, new actual StatementData
            input.extend(execute(7, flags, &tail(&[0, 1, 1, 0, 10])));
            input.extend(frame(&[1]));
            let mut output = Vec::new();
            run_frontier(shim, &input, &mut output, capabilities, 0)
                .await
                .unwrap();
            assert_eq!(errors(&output).await, vec![
                b"\xff\x2b\x07#HY000Malformed communication packet.".to_vec(),
                PRECHECK_ERROR.to_vec(), PRECHECK_ERROR.to_vec(),
                b"\xff\xdb\x04#HY000Unknown prepared statement handler (7) given to mysql_stmt_precheck".to_vec(),
            ]);
            assert_eq!(
                *observed.lock().unwrap(),
                vec![vec![FrontierValue::Int(9)], vec![FrontierValue::Int(10)]]
            );
            assert_eq!(
                current.load(Ordering::SeqCst),
                0,
                "last statement type/packet leases dropped"
            );
        }
    }
}

#[tokio::test]
async fn later_pieces_and_oversize_rejection_preserve_native_setter_before_sticky_error() {
    let shim = FrontierShim {
        limit: 32,
        ..Default::default()
    };
    let observed = shim.values.clone();
    let mut input = frame(b"\x16SELECT ?");
    input.extend(long_data(7, 0, &[b'a'; 16]));
    input.extend(long_data(7, 0, &[b'a'; 16])); // aggregate equality accepted, each frame below limit
    input.extend(long_data(7, 0, b"b")); // rejected, earlier bytes/state remain
                                         // Packet NULL cannot bypass incompatible actual LONG_DATA_VALUE.
    input.extend(execute(7, 0, &[1, 1, 3, 0]));
    // Setter failure clears actual values, but leaves the sticky1105.
    input.extend(execute(7, 0, &[0, 1, 1, 0, 7]));
    input.extend(execute(7, 0, &[0, 0, 8]));
    input.extend(frame(&[0x1a, 7, 0, 0, 0]));
    input.extend(long_data(7, 9, b"bad")); // defer1210
    input.extend(long_data(7, 0, b"later-valid-piece"));
    input.extend(execute(7, 0, &[1, 1, 3, 0])); // later actual piece causes setter1210
    input.extend(execute(7, 0, &[0, 1, 1, 0, 9])); // then defer precheck1210
    input.extend(frame(&[0x1a, 7, 0, 0, 0]));
    input.extend(execute(7, 0, &[0, 0, 10]));
    input.extend(frame(&[1]));
    let mut output = Vec::new();
    run_frontier(
        shim,
        &input,
        &mut output,
        CapabilityFlags::CLIENT_PROTOCOL_41,
        0,
    )
    .await
    .unwrap();
    assert_eq!(
        errors(&output).await,
        vec![
            SETTER_ERROR.to_vec(),
            LONG_DATA_ERROR.to_vec(),
            LONG_DATA_ERROR.to_vec(),
            SETTER_ERROR.to_vec(),
            PRECHECK_ERROR.to_vec()
        ]
    );
    assert_eq!(
        *observed.lock().unwrap(),
        vec![vec![FrontierValue::Int(10)]]
    );
    assert!(
        !output
            .windows(b"later-valid-piece".len())
            .any(|bytes| bytes == b"later-valid-piece"),
        "no secret parameter bytes in ERR"
    );
}

#[tokio::test]
async fn valid_long_data_uses_complete_bytes_once_and_resets_after_real_sql_failure() {
    for fail_sql in [false, true] {
        let shim = FrontierShim {
            fail_sql,
            ..Default::default()
        };
        let observed = shim.values.clone();
        let mut input = frame(b"\x16SELECT ?");
        input.extend(long_data(7, 0, &[0xc3])); // split multibyte and embedded NUL are raw pieces
        input.extend(long_data(7, 0, &[0xa9, 0, 255]));
        input.extend(execute(7, 0, &[1, 1, 254, 0])); // real long data overrides NULL
        input.extend(execute(7, 0, &[0, 0, 1, b'z'])); // normal tail reset, reused STRING
        input.extend(long_data(7, 0, &[])); // empty long data is not SQL NULL
        input.extend(execute(7, 0, &[1, 0]));
        input.extend(frame(&[0x1a, 7, 0, 0, 0]));
        input.extend(execute(7, 0, &[1, 0])); // reset then packet NULL is actual NULL
        input.extend(frame(&[1]));
        let mut output = Vec::new();
        run_frontier(
            shim,
            &input,
            &mut output,
            CapabilityFlags::CLIENT_PROTOCOL_41,
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            *observed.lock().unwrap(),
            vec![
                vec![FrontierValue::Bytes(vec![0xc3, 0xa9, 0, 255], true)],
                vec![FrontierValue::Bytes(b"z".to_vec(), false)],
                vec![FrontierValue::Bytes(vec![], true)],
                vec![FrontierValue::Null],
            ]
        );
        assert_eq!(errors(&output).await.len(), if fail_sql { 4 } else { 0 });
    }
}

#[tokio::test]
async fn response_wake_preserves_partial_new_command_and_compressed_continuation_on_reentry() {
    use super::packet_reader::{compression_frame, PauseAtRead};
    for zstd in [false, true] {
        let first = compression_frame(0, b"\x03\0\0\0a", zstd);
        let second = compression_frame(1, b"bc", zstd);
        let successor = compression_frame(0, b"\x01\0\0\0z", zstd);
        for cut in [
            1,
            6,
            7,
            first.len() - 1,
            first.len(),
            first.len() + 2,
            first.len() + 7,
            first.len() + second.len() - 1,
        ] {
            let input = [first.as_slice(), second.as_slice(), successor.as_slice()].concat();
            let (source, resume, paused) = PauseAtRead::new(input, cut);
            let mut reader = PacketReader::new(source);
            if zstd {
                reader.enable_zstd_compression();
            } else {
                reader.enable_compression();
            }
            reader.set_compressed_sequence(17);
            let outcome = crate::poll_command_response(
                &mut reader,
                async {
                    paused.await.unwrap();
                    Ok::<_, io::Error>(7)
                },
                "actual competing response wake",
            )
            .await;
            assert!(matches!(
                outcome,
                crate::CommandResponseOutcome::Completed(Ok(7))
            ));
            assert_eq!(reader.r.consumed(), cut);
            assert_eq!(
                reader.compressed_sequence(),
                if cut < first.len() { 0 } else { 1 }
            );
            resume.store(true, Ordering::SeqCst);
            let (sequence, packet) = reader.next_async_new_command(None).await.unwrap().unwrap();
            assert_eq!(sequence, 0);
            assert_eq!(packet.as_ref(), b"abc");
            assert_eq!(reader.compressed_sequence(), 2);
            assert_eq!(
                reader
                    .next_async_new_command(None)
                    .await
                    .unwrap()
                    .unwrap()
                    .1
                    .as_ref(),
                b"z"
            );
            assert_eq!(reader.compressed_sequence(), 1);
            assert!(reader.next_async_new_command(None).await.unwrap().is_none());
        }
        let wrong = compression_frame(2, b"bc", zstd);
        let (source, resume, paused) =
            PauseAtRead::new([first.as_slice(), wrong.as_slice()].concat(), first.len());
        let mut reader = PacketReader::new(source);
        if zstd {
            reader.enable_zstd_compression();
        } else {
            reader.enable_compression();
        }
        let outcome = crate::poll_command_response(
            &mut reader,
            async {
                paused.await.unwrap();
                Ok::<_, io::Error>(7)
            },
            "pending bad outer sequence",
        )
        .await;
        assert!(matches!(
            outcome,
            crate::CommandResponseOutcome::Completed(Ok(7))
        ));
        resume.store(true, Ordering::SeqCst);
        let error = reader
            .next_async_new_command(None)
            .await
            .err()
            .expect("actual seq2 is not continuation1");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "compressed MySQL packet out of order: received 2, expected 1"
        );
    }
    let (source, resume, paused) = PauseAtRead::new(b"\x03\0\0\x01abc".to_vec(), 2);
    let mut reader = PacketReader::new(source);
    let outcome = crate::poll_command_response(
        &mut reader,
        async {
            paused.await.unwrap();
            Ok::<_, io::Error>(7)
        },
        "pending bad classic sequence",
    )
    .await;
    assert!(matches!(
        outcome,
        crate::CommandResponseOutcome::Completed(Ok(7))
    ));
    resume.store(true, Ordering::SeqCst);
    let error = reader
        .next_async_new_command(None)
        .await
        .err()
        .expect("wrong initial seq remains rejected");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error.to_string(),
        "MySQL packet out of order: received 1, expected 0"
    );
}

#[tokio::test]
async fn negotiated_zstd_validates_the_actual_byte_before_authentication_and_keeps_zlib_priority() {
    let base = CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_PLUGIN_AUTH;
    let zstd = CapabilityFlags::CLIENT_ZSTD_COMPRESSION_ALGORITHM;
    let zlib = CapabilityFlags::CLIENT_COMPRESS;
    for (client, server, expected_algorithm) in [
        (zstd, zstd, "zstd"),
        (zstd | zlib, zstd | zlib, "zlib"),
        (zstd | zlib, zstd, "zstd"),
        (zstd | zlib, zlib, "zlib"),
        (zstd, CapabilityFlags::empty(), ""),
    ] {
        for level in [
            None,
            Some(0),
            Some(1),
            Some(3),
            Some(22),
            Some(23),
            Some(255),
        ] {
            let capabilities = base | client;
            let mut bytes = capabilities.bits().to_le_bytes().to_vec();
            bytes.extend_from_slice(&1024u32.to_le_bytes());
            bytes.push(45);
            bytes.extend_from_slice(&[0; 23]);
            bytes.extend_from_slice(b"login\0\0mysql_native_password\0");
            if let Some(level) = level {
                bytes.push(level);
            }
            let (remaining, handshake) = crate::commands::client_handshake(&bytes, false).unwrap();
            assert!(remaining.is_empty());
            assert_eq!(handshake.zstd_compression_level, level);
            let shim = Shim::default();
            let calls = Arc::clone(&shim.authenticate_calls);
            let compression = Arc::clone(&shim.compression);
            let mut output = Vec::new();
            let mut intermediary = AsyncMysqlIntermediary {
                client_capabilities: base | server,
                process_use_statement_on_query: false,
                reject_connection_on_dbname_absence: false,
                shim,
                reader: PacketReader::new(&[][..]),
                writer: PacketWriter::new(&mut output),
                zstd_compression_level: 0,
                secure_transport: false,
            };
            let result = intermediary.init_after_ssl(handshake, 1).await;
            let invalid = expected_algorithm == "zstd" && !matches!(level, Some(1..=22));
            if invalid {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
                assert_eq!(
                    error.to_string(),
                    "Invalid zstd compression level for algorithm 'zstd'."
                );
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                assert!(compression.lock().unwrap().is_empty());
                assert_eq!(intermediary.zstd_compression_level, 0);
            } else {
                result.unwrap();
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                let expected_level = match expected_algorithm {
                    "zstd" => level.unwrap(),
                    "zlib" => 6,
                    "" => 0,
                    _ => unreachable!(),
                };
                assert_eq!(
                    *compression.lock().unwrap(),
                    [(expected_algorithm, expected_level)]
                );
                assert_eq!(
                    intermediary.zstd_compression_level,
                    if expected_algorithm == "zstd" {
                        expected_level
                    } else {
                        0
                    }
                );
            }
            drop(intermediary);
            let mut reader = PacketReader::new(output.as_slice());
            let (sequence, packet) = reader.next_async().await.unwrap().unwrap();
            assert_eq!(sequence, 2);
            if invalid {
                assert_eq!(packet[0], 0xff);
                assert_eq!(u16::from_le_bytes([packet[1], packet[2]]), 3923);
                assert_eq!(&packet[3..9], b"#HY000");
                assert_eq!(
                    &packet[9..],
                    b"Invalid zstd compression level for algorithm 'zstd'."
                );
            } else {
                assert_eq!(packet[0], 0);
            }
            assert!(reader.next_async().await.unwrap().is_none());
        }
    }
}

#[tokio::test]
async fn handshake_first_response_is_checked_before_decoding_or_authentication() {
    let capabilities = CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_PLUGIN_AUTH;
    let config = crate::ServerHandshakeConfig {
        version: "8.0.46-wire-fixture".into(),
        connection_id: 19,
        default_auth_plugin: "mysql_native_password".into(),
        scramble: [7; 20],
        server_capabilities: capabilities,
        collation: 45,
        status_flags: crate::StatusFlags::SERVER_STATUS_AUTOCOMMIT,
    };
    let mut handshake = capabilities.bits().to_le_bytes().to_vec();
    handshake.extend_from_slice(&1024u32.to_le_bytes());
    handshake.push(45);
    handshake.extend_from_slice(&[0; 23]);
    handshake.extend_from_slice(b"login\0\0mysql_native_password\0");
    for sequence in [0u8, 1, 2, 255] {
        let mut input = frame(&handshake);
        input[3] = sequence;
        let mut output = Vec::new();
        let result = AsyncMysqlIntermediary::<Shim, _, _>::init_before_ssl_with_config(
            &config,
            input.as_slice(),
            &mut output,
            #[cfg(feature = "tls")]
            &None,
        )
        .await;
        if sequence == 1 {
            let (tls, (response, last, _, _)) = result.unwrap();
            assert!(!tls);
            assert_eq!(last, 1);
            assert_eq!(response.username.as_deref(), Some(&b"login"[..]));
        } else {
            let error = result.err().expect("initial sequence");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(
                error.to_string(),
                format!("MySQL packet out of order: received {sequence}, expected 1")
            );
        }
        let mut reader = PacketReader::new(output.as_slice());
        let (sequence, greeting) = reader.next_async().await.unwrap().unwrap();
        assert_eq!(sequence, 0);
        assert_eq!(greeting[0], 10);
        assert!(reader.next_async().await.unwrap().is_none());
    }
}

#[tokio::test]
async fn next_command_peek_resets_compression_without_resetting_same_exchange_reads() {
    let input = b"\x05\0\0\0\0\0\0\x01\0\0\0a\x05\0\0\0\0\0\0\x01\0\0\0b";
    for zstd in [false, true] {
        let mut reader = PacketReader::new(&input[..]);
        if zstd {
            reader.enable_zstd_compression();
        } else {
            reader.enable_compression();
        }
        reader.set_compressed_sequence(17); // prior command's actual exchange
        let outcome = crate::poll_command_response(
            &mut reader,
            async {
                tokio::task::yield_now().await;
                Ok::<_, io::Error>(7)
            },
            "actual test command peer EOF",
        )
        .await;
        assert!(matches!(
            outcome,
            crate::CommandResponseOutcome::Completed(Ok(7))
        ));
        let (_, deferred) = reader.next_async_new_command(None).await.unwrap().unwrap();
        assert_eq!(deferred.as_ref(), b"a");
        let (_, successor) = reader.next_async_new_command(None).await.unwrap().unwrap();
        assert_eq!(successor.as_ref(), b"b");
        assert!(reader.next_async_new_command(None).await.unwrap().is_none());
    }
    let input = frame(b"\x0e");
    let mut malformed = input.clone();
    malformed[3] = 1;
    let mut output = Vec::new();
    let error = run(Shim::default(), &malformed, &mut output, false)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(
        output.is_empty(),
        "bad first command sequence cannot publish an acknowledgement"
    );
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Slot {
    name: Option<Vec<u8>>,
    code: u16,
    unsigned: bool,
    null: bool,
    bytes: Vec<u8>,
}
fn slots(bindings: &ParsedBindings<'_>) -> Vec<Slot> {
    bindings
        .slots()
        .iter()
        .map(|slot| Slot {
            name: slot.name.map(<[u8]>::to_vec),
            code: slot.type_code,
            unsigned: slot.unsigned,
            null: slot.is_null,
            bytes: slot.raw_value.to_vec(),
        })
        .collect()
}
struct Lease {
    current: Arc<AtomicUsize>,
    bytes: usize,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.current.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}
struct Shim {
    enabled: bool,
    block: bool,
    current: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    query: Arc<Mutex<Vec<(Vec<u8>, Vec<Slot>)>>>,
    execute: Arc<Mutex<Vec<(u8, Vec<Slot>, i64)>>>,
    cancel: Arc<AtomicUsize>,
    finish: Arc<AtomicUsize>,
    starts: Arc<AtomicUsize>,
    parameters: Vec<Column>,
    authenticate_calls: Arc<AtomicUsize>,
    compression: Arc<Mutex<Vec<(&'static str, u8)>>>,
}
impl Default for Shim {
    fn default() -> Self {
        Self {
            enabled: true,
            block: false,
            current: Arc::new(AtomicUsize::new(0)),
            peak: Arc::new(AtomicUsize::new(0)),
            query: Arc::new(Mutex::new(Vec::new())),
            execute: Arc::new(Mutex::new(Vec::new())),
            cancel: Arc::new(AtomicUsize::new(0)),
            finish: Arc::new(AtomicUsize::new(0)),
            starts: Arc::new(AtomicUsize::new(0)),
            parameters: vec![Column {
                database: vec![],
                table: vec![],
                org_table: vec![],
                column: b"?".to_vec(),
                org_column: vec![],
                collen: 4,
                charset: None,
                coltype: ColumnType::MYSQL_TYPE_LONG,
                colflags: ColumnFlags::empty(),
                decimals: Some(0),
            }],
            authenticate_calls: Arc::new(AtomicUsize::new(0)),
            compression: Arc::new(Mutex::new(Vec::new())),
        }
    }
}
#[async_trait]
impl<W: AsyncWrite + Unpin + Send> AsyncMysqlShim<W> for Shim {
    type Error = io::Error;
    async fn authenticate(&self, _: &str, _: &[u8], _: u16, _: bool, _: &[u8], _: &[u8]) -> bool {
        self.authenticate_calls.fetch_add(1, Ordering::SeqCst);
        true
    }
    fn on_compression(&mut self, algorithm: &'static str, level: u8) {
        self.compression.lock().unwrap().push((algorithm, level));
    }
    fn query_attributes_admission(&self) -> Option<CommandAllocationAdmission> {
        if !self.enabled {
            return None;
        }
        let current = self.current.clone();
        let peak = self.peak.clone();
        Some(Arc::new(move |bytes| {
            let next = current.fetch_add(bytes, Ordering::SeqCst) + bytes;
            peak.fetch_max(next, Ordering::SeqCst);
            Ok(Arc::new(Lease {
                current: current.clone(),
                bytes,
            }))
        }))
    }
    async fn on_prepare<'a>(
        &'a mut self,
        _: &'a [u8],
        info: StatementMetaWriter<'a, W>,
    ) -> io::Result<()> {
        info.reply(7, &self.parameters, &[]).await
    }
    async fn on_execute<'a>(
        &'a mut self,
        _: u32,
        params: ParamParser<'a>,
        results: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        let values = params.parse()?;
        assert_eq!(values[0].value.into_inner(), ValueInner::Int(7));
        self.starts.fetch_add(1, Ordering::SeqCst);
        if self.block {
            std::future::pending::<()>().await;
        }
        results.completed(OkResponse::default()).await
    }
    async fn on_close<'a>(&'a mut self, _: u32) {}
    async fn on_execute_cursor<'a>(
        &'a mut self,
        _: u32,
        params: ParamParser<'a>,
        results: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        let values = params.parse()?;
        assert_eq!(values[0].value.into_inner(), ValueInner::Int(7));
        self.starts.fetch_add(1, Ordering::SeqCst);
        if self.block {
            std::future::pending::<()>().await;
        }
        results.completed(OkResponse::default()).await
    }
    async fn on_query<'a>(
        &'a mut self,
        query: &'a [u8],
        results: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        self.query.lock().unwrap().push((query.to_vec(), vec![]));
        results.completed(OkResponse::default()).await
    }
    async fn on_query_bindings<'a>(
        &'a mut self,
        bindings: ParsedBindings<'a>,
        results: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        let owner = bindings
            .packet_owner()
            .expect("actual dispatch packet owner");
        assert_eq!(
            &owner[bindings.packet_range(bindings.suffix()).unwrap()],
            bindings.suffix()
        );
        for slot in bindings.slots() {
            if let Some(name) = slot.name {
                assert_eq!(&owner[bindings.packet_range(name).unwrap()], name);
            }
            if !slot.is_null && !slot.is_long_data {
                assert_eq!(
                    &owner[bindings.packet_range(slot.raw_value).unwrap()],
                    slot.raw_value
                );
            }
        }
        self.query
            .lock()
            .unwrap()
            .push((bindings.suffix().to_vec(), slots(&bindings)));
        if self.block {
            assert!(self.current.load(Ordering::SeqCst) > 0);
            std::future::pending::<()>().await;
        }
        results.completed(OkResponse::default()).await
    }
    async fn on_execute_bindings<'a>(
        &'a mut self,
        _: u32,
        mut bindings: ParsedBindings<'a>,
        results: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        let observed = slots(&bindings);
        let owner = bindings
            .packet_owner()
            .expect("actual dispatch packet owner");
        for slot in bindings.slots() {
            if let Some(name) = slot.name {
                assert_eq!(&owner[bindings.packet_range(name).unwrap()], name);
            }
            if !slot.is_null && !slot.is_long_data {
                assert_eq!(
                    &owner[bindings.packet_range(slot.raw_value).unwrap()],
                    slot.raw_value
                );
            }
        }
        let parameters = match bindings.bind_placeholders() {
            Ok(parameters) => parameters,
            Err(error) => {
                if let Some(kind) = error.error_kind() {
                    return results.error(kind, error.message()).await;
                }
                return Err(error.into_io());
            }
        };
        let ValueInner::Int(value) = parameters[0].value.into_inner() else {
            panic!("real first placeholder must retain signed integer");
        };
        self.execute
            .lock()
            .unwrap()
            .push((bindings.execute_flags(), observed, value));
        results.completed(OkResponse::default()).await
    }
    async fn on_query_finished(&mut self) -> io::Result<()> {
        self.finish.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn on_query_cancelled(&mut self) -> io::Result<()> {
        self.cancel.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = payload.len().to_le_bytes()[..3].to_vec();
    bytes.push(0);
    bytes.extend_from_slice(payload);
    bytes
}

#[tokio::test]
async fn cursor_open_peer_eof_uses_the_same_cancellation_frontier_without_query_finish() {
    let shim = Shim {
        block: true,
        ..Default::default()
    };
    let starts = shim.starts.clone();
    let cancel = shim.cancel.clone();
    let finish = shim.finish.clone();
    let mut input = frame(b"\x16SELECT ?");
    input.extend(execute(7, 1, &[0, 1, 3, 0, 7, 0, 0, 0]));
    let mut output = Vec::new();
    let error = run(shim, &input, &mut output, false).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(cancel.load(Ordering::SeqCst), 1);
    assert_eq!(
        finish.load(Ordering::SeqCst),
        0,
        "cursor opening is not final query EOF"
    );
    assert!(
        errors(&output).await.is_empty(),
        "disconnect must not fabricate an SQL ERR"
    );
    let mut reader = PacketReader::new(output.as_slice());
    let (_, prepare_ok) = reader.next_async().await.unwrap().unwrap();
    assert_eq!(prepare_ok[0], 0);
    assert_eq!(&prepare_ok[1..5], &7u32.to_le_bytes());
    // The remaining packets belong to PREPARE metadata only; the pending
    // cursor producer emitted no success rowset or cursor-open terminator.
    while let Some((_, packet)) = reader.next_async().await.unwrap() {
        assert_ne!(
            packet.first(),
            Some(&0),
            "no cursor command acknowledgement"
        );
    }
}

#[tokio::test]
async fn prepared_execution_bad_successor_sequence_cancels_before_success_or_query_finish() {
    let shim = Shim {
        block: true,
        ..Default::default()
    };
    let starts = shim.starts.clone();
    let cancelled = shim.cancel.clone();
    let finished = shim.finish.clone();
    let mut input = frame(b"\x16SELECT ?");
    input.extend(execute(7, 0, &[0, 1, 3, 0, 7, 0, 0, 0]));
    let mut successor = frame(&[0x0e]);
    successor[3] = 9;
    input.extend(successor);
    let mut output = Vec::new();
    let error = run(shim, &input, &mut output, false).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error.to_string(),
        "MySQL packet out of order: received 9, expected 0"
    );
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(cancelled.load(Ordering::SeqCst), 1);
    assert_eq!(finished.load(Ordering::SeqCst), 0);
    assert!(errors(&output).await.is_empty());
}
async fn run(shim: Shim, input: &[u8], output: &mut Vec<u8>, named: bool) -> io::Result<()> {
    let mut capabilities = CapabilityFlags::CLIENT_PROTOCOL_41;
    capabilities.set(CapabilityFlags::CLIENT_QUERY_ATTRIBUTES, named);
    let mut intermediary = AsyncMysqlIntermediary {
        client_capabilities: capabilities,
        process_use_statement_on_query: false,
        reject_connection_on_dbname_absence: false,
        shim,
        reader: PacketReader::new(input),
        writer: PacketWriter::new(output),
        zstd_compression_level: 0,
        secure_transport: false,
    };
    intermediary.run_commands().await
}
fn query(sql: &[u8]) -> Vec<u8> {
    let mut bytes = vec![3, 1, 1, 0, 1, 1, 0, 1, b'a', 7];
    bytes.extend_from_slice(sql);
    frame(&bytes)
}
fn execute(id: u32, flags: u8, tail: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x17];
    bytes.extend_from_slice(&id.to_le_bytes());
    bytes.push(flags);
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(tail);
    frame(&bytes)
}
async fn errors(output: &[u8]) -> Vec<Vec<u8>> {
    let mut reader = PacketReader::new(output);
    let mut errors = Vec::new();
    while let Some((_, packet)) = reader.next_async().await.unwrap() {
        if packet[0] == 0xff {
            errors.push(packet.to_vec());
        }
    }
    errors
}

#[test]
fn capability_is_removed_without_the_actual_shim_allocation_issuer() {
    let base = CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_QUERY_ATTRIBUTES;
    assert_eq!(
        query_attribute_capabilities(base, false),
        CapabilityFlags::CLIENT_PROTOCOL_41
    );
    assert_eq!(
        query_attribute_capabilities(CapabilityFlags::CLIENT_PROTOCOL_41, true),
        base
    );
}

#[tokio::test]
async fn actual_query_envelope_strips_only_negotiated_framing_and_does_not_leak_to_successor() {
    let shim = Shim::default();
    let query_rows = shim.query.clone();
    let current = shim.current.clone();
    let peak = shim.peak.clone();
    let finish = shim.finish.clone();
    let mut input = query(b"USE db"); // named USE cannot bypass this callback
    input.extend(frame(b"\x03\0\x01SELECT 2"));
    input.extend(frame(&[1]));
    let mut output = Vec::new();
    run(shim, &input, &mut output, true).await.unwrap();
    let rows = query_rows.lock().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0, b"USE db");
    assert_eq!(
        rows[0].1,
        vec![Slot {
            name: Some(b"a".to_vec()),
            code: 1,
            unsigned: false,
            null: false,
            bytes: vec![7]
        }]
    );
    assert_eq!(rows[1], (b"SELECT 2".to_vec(), vec![]));
    assert_eq!(current.load(Ordering::SeqCst), 0);
    assert!(peak.load(Ordering::SeqCst) >= std::mem::size_of::<crate::RawParamValue<'_>>());
    assert_eq!(finish.load(Ordering::SeqCst), 2);
    assert!(errors(&output).await.is_empty());
}

#[tokio::test]
async fn unknown_statement_precedes_bad_tail_and_short_header_is_native_malformed() {
    let shim = Shim::default();
    let peak = shim.peak.clone();
    let mut input = execute(99, 8, &[255]);
    input.extend(frame(&[0x17, 99]));
    input.extend(frame(&[1]));
    let mut output = Vec::new();
    run(shim, &input, &mut output, true).await.unwrap();
    let errors = errors(&output).await;
    assert_eq!(errors.len(), 2);
    assert_eq!(
        &errors[0],
        b"\xff\xdb\x04#HY000Unknown prepared statement handler (99) given to mysql_stmt_precheck"
    );
    assert_eq!(
        &errors[1],
        b"\xff\x2b\x07#HY000Malformed communication packet."
    );
    assert_eq!(peak.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn execute_flag8_reset_and_reuse_share_only_actual_placeholder_source_types() {
    let shim = Shim::default();
    let observed = shim.execute.clone();
    let current = shim.current.clone();
    let mut input = frame(b"\x16SELECT ?");
    // N=2, named P=1 plus attr, new types. No parameter-set byte.
    input.extend(execute(
        7,
        9,
        &[2, 0, 1, 1, 0, 1, b'p', 1, 0, 1, b'a', 7, 9],
    ));
    input.extend(frame(&[0x1a, 7, 0, 0, 0]));
    input.extend(execute(7, 8, &[1, 0, 0, 11])); // reset retained source type
    input.extend(frame(&[0x19, 7, 0, 0, 0]));
    input.extend(execute(7, 8, &[255])); // close -> lookup wins
    input.extend(frame(&[1]));
    let mut output = Vec::new();
    run(shim, &input, &mut output, true).await.unwrap();
    let rows = observed.lock().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0, 9);
    assert_eq!(rows[0].2, 7);
    assert_eq!(rows[0].1.len(), 2);
    assert_eq!(rows[0].1[0].name, Some(b"p".to_vec()));
    assert_eq!(rows[0].1[1].name, Some(b"a".to_vec()));
    assert_eq!(
        rows[1],
        (
            8,
            vec![Slot {
                name: None,
                code: 1,
                unsigned: false,
                null: false,
                bytes: vec![11]
            }],
            11
        )
    );
    let errors = errors(&output).await;
    assert_eq!(errors.len(), 1);
    assert_eq!(
        &errors[0],
        b"\xff\xdb\x04#HY000Unknown prepared statement handler (7) given to mysql_stmt_precheck"
    );
    assert_eq!(current.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn eof_cancels_the_actual_pending_query_and_releases_its_slot_allocation() {
    let shim = Shim {
        block: true,
        ..Default::default()
    };
    let current = shim.current.clone();
    let peak = shim.peak.clone();
    let cancel = shim.cancel.clone();
    let finish = shim.finish.clone();
    let starts = shim.starts.clone();
    let mut output = Vec::new();
    let error = run(shim, &query(b"SELECT 1"), &mut output, true)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(cancel.load(Ordering::SeqCst), 1);
    assert_eq!(finish.load(Ordering::SeqCst), 0);
    assert!(output.is_empty());
    assert!(peak.load(Ordering::SeqCst) > 0);
    assert_eq!(current.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn packet_range_is_the_same_allocation_across_reader_poll_and_last_owner_drop() {
    let mut input = frame(b"first");
    input.extend(frame(b"second"));
    let mut reader = PacketReader::new(input.as_slice());
    let (_, first) = reader.next_async().await.unwrap().unwrap();
    let cloned = first.clone();
    let owned = first.owned_range(1..5).unwrap();
    assert_eq!(owned.as_ptr(), first[1..].as_ptr());
    assert_eq!(owned, &b"irst"[..]);
    assert_eq!(
        first.owned_range(6..7).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    let (_, second) = reader.next_async().await.unwrap().unwrap();
    assert_eq!(&second[..], b"second");
    drop(first);
    drop(cloned);
    drop(reader);
    assert_eq!(owned, &b"irst"[..]);
}

#[tokio::test]
async fn reset_connection_drops_only_the_actual_statement_and_its_type_lease() {
    let shim = Shim::default();
    let observed = shim.execute.clone();
    let current = shim.current.clone();
    let mut input = frame(b"\x16SELECT ?");
    input.extend(execute(7, 8, &[1, 0, 1, 1, 0, 0, 7]));
    input.extend(frame(&[0x1f]));
    input.extend(execute(7, 8, &[255]));
    input.extend(frame(&[1]));
    let mut output = Vec::new();
    run(shim, &input, &mut output, true).await.unwrap();
    assert_eq!(observed.lock().unwrap().len(), 1);
    assert_eq!(current.load(Ordering::SeqCst), 0);
    assert_eq!(errors(&output).await,
        vec![b"\xff\xdb\x04#HY000Unknown prepared statement handler (7) given to mysql_stmt_precheck".to_vec()]);
}

#[tokio::test]
async fn actual_wire_framing_precheck_and_source_setter_failures_keep_distinct_identity() {
    let shim = Shim::default();
    let current = shim.current.clone();
    let mut input = frame(b"\x16SELECT ?");
    input.extend(execute(7, 8, &[1, 0, 1, 1])); // malformed descriptor
    input.extend(execute(7, 8, &[0])); // complete N<P
    input.extend(execute(7, 8, &[1, 1, 1, 1, 1, 0])); // NULL invalid type 257
    input.extend(frame(&[1]));
    let mut output = Vec::new();
    run(shim, &input, &mut output, true).await.unwrap();
    assert_eq!(
        errors(&output).await,
        vec![
            b"\xff\x2b\x07#HY000Malformed communication packet.".to_vec(),
            b"\xff\xba\x04#HY000Incorrect arguments to COM_STMT_EXECUTE".to_vec(),
            b"\xff\xba\x04#HY000Incorrect arguments to mysqld_stmt_execute".to_vec(),
        ]
    );
    assert_eq!(current.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn nonnegotiated_query_bytes_are_never_interpreted_as_attribute_headers() {
    let shim = Shim {
        enabled: false,
        ..Default::default()
    };
    let observed = shim.query.clone();
    let peak = shim.peak.clone();
    let mut input = frame(b"\x03\0\x01SELECT 1");
    input.extend(frame(&[1]));
    let mut output = Vec::new();
    run(shim, &input, &mut output, false).await.unwrap();
    assert_eq!(
        *observed.lock().unwrap(),
        vec![(b"\0\x01SELECT 1".to_vec(), vec![])]
    );
    assert_eq!(peak.load(Ordering::SeqCst), 0);
    assert!(errors(&output).await.is_empty());
}

struct DefaultConsumer;
#[async_trait]
impl<W: AsyncWrite + Unpin + Send> AsyncMysqlShim<W> for DefaultConsumer {
    type Error = io::Error;
    fn query_attributes_admission(&self) -> Option<CommandAllocationAdmission> {
        Some(Arc::new(|_| Ok(Arc::new(()))))
    }
    async fn on_prepare<'a>(
        &'a mut self,
        _: &'a [u8],
        _: StatementMetaWriter<'a, W>,
    ) -> io::Result<()> {
        panic!("not used")
    }
    async fn on_execute<'a>(
        &'a mut self,
        _: u32,
        _: ParamParser<'a>,
        _: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        panic!("negotiated bindings must not silently reach legacy consumer");
    }
    async fn on_close<'a>(&'a mut self, _: u32) {}
    async fn on_query<'a>(
        &'a mut self,
        _: &'a [u8],
        _: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        panic!("negotiated bindings must not silently reach legacy consumer");
    }
}

#[tokio::test]
async fn external_shim_default_statistics_refuses_absent_global_producers() {
    let mut output = Vec::new();
    let mut writer = PacketWriter::new(&mut output);
    writer.set_seq(1);
    DefaultConsumer
        .on_statistics(StatisticsWriter {
            writer: &mut writer,
        })
        .await
        .unwrap();
    writer.flush_all().await.unwrap();
    drop(writer);
    let mut reader = PacketReader::new(output.as_slice());
    let (sequence, packet) = reader.next_async().await.unwrap().unwrap();
    assert_eq!(sequence, 1);
    assert_eq!(
        packet.as_ref(),
        b"\xff\xd3\x04#42000COM_STATISTICS global producers are not installed"
    );
    assert!(reader.next_async().await.unwrap().is_none());
}

#[tokio::test]
async fn default_negotiated_consumer_refuses_attributes_instead_of_discarding_them() {
    let input = query(b"SELECT 1");
    let mut output = Vec::new();
    let bindings = ParamParser::query(
        &input[5..],
        true,
        <DefaultConsumer as AsyncMysqlShim<Vec<u8>>>::query_attributes_admission(&DefaultConsumer),
    )
    .parse_bindings()
    .unwrap();
    let mut writer = PacketWriter::new(&mut output);
    let results = QueryResultWriter::new(&mut writer, false, CapabilityFlags::CLIENT_PROTOCOL_41);
    DefaultConsumer
        .on_query_bindings(bindings, results)
        .await
        .unwrap();
    writer.flush_all().await.unwrap();
    drop(writer);
    assert_eq!(
        errors(&output).await,
        vec![
            b"\xff\xd3\x04#42000negotiated query bindings require an installed command consumer"
                .to_vec()
        ]
    );
}

#[tokio::test]
async fn initial_database_default_acceptance_and_operational_write_error_remain_distinct() {
    // The external default is the unchanged on_init no-op contract. It does
    // not assert an authenticated principal or manufacture an OK/SQL error.
    let mut output = Vec::new();
    let mut writer = PacketWriter::new(&mut output);
    let accepted = <DefaultConsumer as AsyncMysqlShim<&mut Vec<u8>>>::on_initial_database(
        &mut DefaultConsumer,
        b"",
        InitWriter {
            client_capabilities: CapabilityFlags::CLIENT_PROTOCOL_41,
            writer: &mut writer,
        },
    )
    .await
    .unwrap();
    assert!(accepted);
    writer.flush_all().await.unwrap();
    drop(writer);
    assert!(output.is_empty());

    let mut shim = FrontierShim {
        init_error: true,
        ..Default::default()
    };
    let mut writer = PacketWriter::new(FailedWriter);
    let error = <FrontierShim as AsyncMysqlShim<FailedWriter>>::on_initial_database(
        &mut shim,
        b"bad_db",
        InitWriter {
            client_capabilities: CapabilityFlags::CLIENT_PROTOCOL_41,
            writer: &mut writer,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(shim.read_calls.load(Ordering::SeqCst), 0);
    assert!(shim.command_frontiers.lock().unwrap().is_empty());
}

struct FailedWriter;
impl AsyncWrite for FailedWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::task::Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "actual writer failed",
        )))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn actual_response_write_failure_releases_query_slots_without_a_successor() {
    let shim = Shim::default();
    let current = shim.current.clone();
    let observed = shim.query.clone();
    let input = query(b"SELECT 1");
    let mut intermediary = AsyncMysqlIntermediary {
        client_capabilities: CapabilityFlags::CLIENT_PROTOCOL_41
            | CapabilityFlags::CLIENT_QUERY_ATTRIBUTES,
        process_use_statement_on_query: false,
        reject_connection_on_dbname_absence: false,
        shim,
        reader: PacketReader::new(input.as_slice()),
        writer: PacketWriter::new(FailedWriter),
        zstd_compression_level: 0,
        secure_transport: false,
    };
    let error = intermediary.run_commands().await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(observed.lock().unwrap().len(), 1);
    assert_eq!(current.load(Ordering::SeqCst), 0);
}
#[test]
fn external_default_tls_callback_is_fallible_compatible_but_does_not_invent_sql_facts() {
    let mut shim = FrontierShim::default();
    <FrontierShim as AsyncMysqlShim<tokio::io::DuplexStream>>::on_tls_session(
        &mut shim,
        crate::TlsSessionInfo {
            cipher: "TLS_AES_128_GCM_SHA256",
            version: "TLSv1.3",
            reused: false,
        },
        &[],
    )
    .unwrap();
    assert!(shim.values.lock().unwrap().is_empty());
    assert!(shim.changed.lock().unwrap().is_empty());
    assert!(shim.command_frontiers.lock().unwrap().is_empty());
    assert_eq!(shim.statistics_calls.load(Ordering::Relaxed), 0);
    assert_eq!(crate::TlsSessionInfo::NO_SSL.cipher, "");
    assert_eq!(crate::TlsSessionInfo::NO_SSL.version, "");
    assert!(!crate::TlsSessionInfo::NO_SSL.reused);
}
