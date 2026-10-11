use super::super::{
    decode_caching_sha2_full_auth, AsyncMysqlIntermediary, AsyncMysqlShim, CachingSha2PasswordAuth,
    ParamParser, QueryResultWriter, StatementMetaWriter,
};
use crate::packet_reader::PacketReader;
use crate::packet_writer::PacketWriter;
use crate::CapabilityFlags;
use async_trait::async_trait;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn parse_change_user<'a>(
    payload: &'a [u8],
    capabilities: CapabilityFlags,
) -> io::Result<super::super::ChangeUserRequest<'a>> {
    // The original IO assertions still exercise the same one-pass parser.
    super::super::parse_change_user_native(payload, capabilities).map_err(|(error, _)| error)
}

#[test]
fn change_user_database_is_an_original_raw_span_not_a_decoded_name() {
    for (charset, user, database) in [
        (8u16, &b"caf\xe9"[..], &b"db_\xe9"[..]),
        (28, &b"gbk_\x81\x5c"[..], &b"db_\x81\x5c"[..]),
        (45, "用户".as_bytes(), "数据库".as_bytes()),
        (65_535, &b"\xff"[..], &b"db_\xc3"[..]),
    ] {
        let mut bytes = user.to_vec();
        bytes.extend_from_slice(&[0, 0]);
        let database_offset = bytes.len();
        bytes.extend_from_slice(database);
        bytes.push(0);
        bytes.extend_from_slice(&charset.to_le_bytes());
        bytes.extend_from_slice(b"mysql_native_password\0");
        let parsed = parse_change_user(&bytes, CapabilityFlags::CLIENT_PLUGIN_AUTH).unwrap();
        assert_eq!(parsed.username, user);
        assert_eq!(parsed.username.as_ptr(), bytes.as_ptr());
        assert_eq!(parsed.database, Some(database));
        assert_eq!(
            parsed.database.unwrap().as_ptr(),
            bytes[database_offset..].as_ptr()
        );
        assert_eq!(parsed.character_set, charset);
        assert_eq!(parsed.plugin, Some("mysql_native_password"));
    }
}

#[tokio::test]
async fn original_sha2_switch_and_full_auth_keep_the_same_packet_charset() {
    for charset in [8u16, 28, 45, 65_535] {
        let shim = auth_shim("caching_sha2_password", true);
        let recorded = Arc::clone(&shim.charsets);
        let input = [framed(2, b"fast"), framed(4, b"secret\0")].concat();
        let mut intermediary = auth_intermediary(shim, &input, true);
        let result = intermediary
            .authenticate_exchange(
                b"raw_\xff",
                charset,
                false,
                Some("different_plugin"),
                b"salt",
                b"ignored",
                0,
            )
            .await
            .unwrap();
        assert_eq!(result, (true, 4, true));
        assert!(
            intermediary
                .apply_authentication_result(b"raw_\xff", charset, false, true)
                .await
        );
        assert_eq!(
            *recorded.lock().unwrap(),
            [
                ("plugin", charset, false),
                ("caching", charset, false),
                ("caching", charset, false),
                ("cleartext", charset, false),
                ("result", charset, false),
            ]
        );
    }
}

#[test]
fn cleartext_full_auth_candidate_is_transient_and_nul_terminated() {
    assert_eq!(
        decode_caching_sha2_full_auth("unused", b"nonce", b"secret\0", true),
        Some(b"secret".to_vec())
    );
    assert_eq!(
        decode_caching_sha2_full_auth("unused", b"nonce", b"secret", true),
        None
    );
}

#[test]
fn insecure_transport_never_accepts_cleartext_full_auth() {
    assert_eq!(
        decode_caching_sha2_full_auth("unused", b"nonce", b"secret\0", false),
        None
    );
}

#[test]
fn rsa_full_auth_uses_oaep_and_removes_the_terminal_nul() {
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::rand_core::OsRng;
    use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};

    let private = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public = RsaPublicKey::from(&private);
    let salt = b"01234567890123456789";
    let mut wire_candidate = b"secret\0".to_vec();
    for (index, byte) in wire_candidate.iter_mut().enumerate() {
        *byte ^= salt[index % salt.len()];
    }
    let encrypted = public
        .encrypt(&mut OsRng, Oaep::new::<sha1::Sha1>(), &wire_candidate)
        .unwrap();
    let private_pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
    assert_eq!(
        decode_caching_sha2_full_auth(private_pem.as_str(), salt, &encrypted, false),
        Some(b"secret".to_vec())
    );
}

fn change_user_payload(length: &[u8], auth_data: &[u8]) -> Vec<u8> {
    let mut payload = b"next_user\0".to_vec();
    payload.extend_from_slice(length);
    payload.extend_from_slice(auth_data);
    payload.extend_from_slice(b"next_db\0");
    payload.extend_from_slice(&45u16.to_le_bytes());
    payload.extend_from_slice(b"caching_sha2_password\0");
    payload
}

#[tokio::test]
async fn authentication_switch_checks_the_actual_outgoing_packet_sequence_before_plugin_proof() {
    for previous in [0u8, 254, 255] {
        for valid in [true, false] {
            let shim = auth_shim("mysql_native_password", false);
            let calls = Arc::clone(&shim.authenticate_calls);
            let expected = previous.wrapping_add(2);
            let actual = if valid {
                expected
            } else {
                expected.wrapping_add(1)
            };
            let input = framed(actual, b"switched");
            let mut intermediary = auth_intermediary(shim, &input, false);
            let result = intermediary
                .authenticate_exchange(
                    b"next_user",
                    45,
                    false,
                    Some("wrong_plugin"),
                    b"salt",
                    b"ignored",
                    previous,
                )
                .await;
            if valid {
                assert_eq!(result.unwrap(), (true, expected, true));
                assert_eq!(calls.load(Ordering::Relaxed), 1);
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert_eq!(
                    error.to_string(),
                    format!("MySQL packet out of order: received {actual}, expected {expected}")
                );
                assert_eq!(calls.load(Ordering::Relaxed), 0);
            }
        }
    }
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn ssl_request_continuation_does_not_reset_the_handshake_exchange() {
    let shim = auth_shim("mysql_native_password", false);
    let calls = Arc::clone(&shim.authenticate_calls);
    let input = framed(3, b"");
    let mut intermediary = auth_intermediary(shim, &input, true);
    let handshake = crate::commands::ClientHandshake {
        maxps: 1024,
        capabilities: CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_SSL,
        collation: 45,
        db: None,
        username: None,
        auth_response: Vec::new(),
        auth_plugin: Vec::new(),
        connection_attrs: Vec::new(),
        zstd_compression_level: None,
    };
    let error = intermediary.init_after_ssl(handshake, 1).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error.to_string(),
        "MySQL packet out of order: received 3, expected 2"
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[test]
fn change_user_auth_length_is_one_byte_even_with_handshake_lenenc_capability() {
    for extra in [
        CapabilityFlags::empty(),
        CapabilityFlags::CLIENT_SECURE_CONNECTION,
        CapabilityFlags::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA,
    ] {
        for length in [0u8, 1, 250, 251, 252, 253, 254, 255] {
            let capabilities = CapabilityFlags::CLIENT_PLUGIN_AUTH | extra;
            let auth_data = vec![7; usize::from(length)];
            let payload = change_user_payload(&[length], &auth_data);
            let request = parse_change_user(&payload, capabilities).unwrap();
            assert_eq!(request.username, b"next_user");
            assert_eq!(request.auth_data, auth_data);
            assert_eq!(request.database, Some(&b"next_db"[..]));
            assert_eq!(request.character_set, 45);
            assert_eq!(request.plugin, Some("caching_sha2_password"));
            assert!(request.connection_attrs.is_empty());
        }
    }
}

#[test]
fn change_user_decodes_connection_attributes() {
    let capabilities = CapabilityFlags::CLIENT_PLUGIN_AUTH
        | CapabilityFlags::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
        | CapabilityFlags::CLIENT_CONNECT_ATTRS;
    let mut payload = change_user_payload(&[1], &[1]);
    let attributes = b"\x04key1\x06value1\x04_key\x06_value";
    payload.push(attributes.len() as u8);
    payload.extend_from_slice(attributes);
    let request = parse_change_user(&payload, capabilities).unwrap();
    assert_eq!(
        request.connection_attrs,
        vec![
            (b"key1".to_vec(), b"value1".to_vec()),
            (b"_key".to_vec(), b"_value".to_vec())
        ]
    );
}

#[test]
fn change_user_rejects_truncation_missing_attributes_and_trailing_bytes() {
    let capabilities = CapabilityFlags::CLIENT_PLUGIN_AUTH
        | CapabilityFlags::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;
    assert!(parse_change_user(b"user\0\xfb", capabilities).is_err());
    assert!(parse_change_user(b"user\0\xfc\x02\x00\x01", capabilities).is_err());
    let mut trailing = change_user_payload(&[1], &[1]);
    trailing.push(0xff);
    assert!(parse_change_user(&trailing, capabilities).is_err());
    let capabilities = capabilities | CapabilityFlags::CLIENT_CONNECT_ATTRS;
    let mut attrs = change_user_payload(&[1], &[1]);
    assert!(parse_change_user(&attrs, capabilities).is_err());
    attrs.extend_from_slice(&[0xfd, 0, 0, 1]);
    attrs.extend_from_slice(&vec![0; 65_536]);
    let error = parse_change_user(&attrs, capabilities).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error.to_string(),
        "COM_CHANGE_USER connection attributes exceed 65535 bytes"
    );
}

#[derive(Clone)]
struct AuthShim {
    plugin: &'static str,
    force_full: bool,
    empty_password: bool,
    authenticate_calls: Arc<AtomicUsize>,
    cleartext_calls: Arc<AtomicUsize>,
    result_calls: Arc<AtomicUsize>,
    result_allowed: bool,
    charsets: Arc<Mutex<Vec<(&'static str, u16, bool)>>>,
}

#[async_trait]
impl AsyncMysqlShim<tokio::io::Sink> for AuthShim {
    type Error = io::Error;

    async fn auth_plugin_for_username(
        &self,
        _user: &[u8],
        character_set: u16,
        initial_handshake: bool,
    ) -> &'static str {
        self.charsets
            .lock()
            .unwrap()
            .push(("plugin", character_set, initial_handshake));
        self.plugin
    }

    async fn authenticate(
        &self,
        _auth_plugin: &str,
        _username: &[u8],
        character_set: u16,
        initial_handshake: bool,
        _salt: &[u8],
        auth_data: &[u8],
    ) -> bool {
        self.charsets
            .lock()
            .unwrap()
            .push(("proof", character_set, initial_handshake));
        self.authenticate_calls.fetch_add(1, Ordering::Relaxed);
        if self.empty_password {
            auth_data.is_empty() || auth_data == [0]
        } else {
            auth_data == b"switched" || auth_data == b"fast"
        }
    }

    async fn caching_sha2_password_auth(
        &self,
        _username: &[u8],
        character_set: u16,
        initial_handshake: bool,
        _salt: &[u8],
        _initial_response: &[u8],
    ) -> Option<CachingSha2PasswordAuth> {
        self.charsets
            .lock()
            .unwrap()
            .push(("caching", character_set, initial_handshake));
        (self.plugin == "caching_sha2_password").then(|| CachingSha2PasswordAuth {
            public_key_pem: String::new(),
            private_key_pem: String::new(),
            force_full_auth: self.force_full,
        })
    }

    async fn authenticate_cleartext(
        &self,
        _auth_plugin: &str,
        _username: &[u8],
        character_set: u16,
        initial_handshake: bool,
        candidate: &[u8],
    ) -> bool {
        self.charsets
            .lock()
            .unwrap()
            .push(("cleartext", character_set, initial_handshake));
        self.cleartext_calls.fetch_add(1, Ordering::Relaxed);
        candidate == b"secret"
    }

    async fn on_authentication_result(
        &mut self,
        _username: &[u8],
        character_set: u16,
        initial_handshake: bool,
        _authenticated: bool,
    ) -> bool {
        self.charsets
            .lock()
            .unwrap()
            .push(("result", character_set, initial_handshake));
        self.result_calls.fetch_add(1, Ordering::Relaxed);
        self.result_allowed
    }

    async fn on_prepare<'a>(
        &'a mut self,
        _query: &'a [u8],
        _info: StatementMetaWriter<'a, tokio::io::Sink>,
    ) -> Result<(), Self::Error> {
        unreachable!()
    }

    async fn on_execute<'a>(
        &'a mut self,
        _id: u32,
        _params: ParamParser<'a>,
        _results: QueryResultWriter<'a, tokio::io::Sink>,
    ) -> Result<(), Self::Error> {
        unreachable!()
    }

    async fn on_close<'a>(&'a mut self, _stmt: u32) {}

    async fn on_query<'a>(
        &'a mut self,
        _query: &'a [u8],
        _results: QueryResultWriter<'a, tokio::io::Sink>,
    ) -> Result<(), Self::Error> {
        unreachable!()
    }
}

fn framed(seq: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = payload.len().to_le_bytes()[..3].to_vec();
    frame.push(seq);
    frame.extend_from_slice(payload);
    frame
}

fn auth_intermediary<'a>(
    shim: AuthShim,
    input: &'a [u8],
    secure_transport: bool,
) -> AsyncMysqlIntermediary<AuthShim, &'a [u8], tokio::io::Sink> {
    AsyncMysqlIntermediary {
        client_capabilities: CapabilityFlags::empty(),
        process_use_statement_on_query: false,
        reject_connection_on_dbname_absence: false,
        shim,
        reader: PacketReader::new(input),
        writer: PacketWriter::new(tokio::io::sink()),
        zstd_compression_level: 0,
        secure_transport,
    }
}

fn auth_shim(plugin: &'static str, force_full: bool) -> AuthShim {
    AuthShim {
        plugin,
        force_full,
        empty_password: false,
        authenticate_calls: Arc::new(AtomicUsize::new(0)),
        cleartext_calls: Arc::new(AtomicUsize::new(0)),
        result_calls: Arc::new(AtomicUsize::new(0)),
        result_allowed: true,
        charsets: Arc::new(Mutex::new(Vec::new())),
    }
}

#[tokio::test]
async fn authentication_result_hook_runs_once_and_can_only_downgrade() {
    let mut reject = auth_shim("mysql_native_password", false);
    reject.result_allowed = false;
    let reject_calls = Arc::clone(&reject.result_calls);
    let mut intermediary = auth_intermediary(reject, &[], false);
    assert!(
        !intermediary
            .apply_authentication_result(b"account", 45, false, true)
            .await
    );
    assert_eq!(reject_calls.load(Ordering::Relaxed), 1);

    let accept = auth_shim("mysql_native_password", false);
    let accept_calls = Arc::clone(&accept.result_calls);
    let mut intermediary = auth_intermediary(accept, &[], false);
    assert!(
        !intermediary
            .apply_authentication_result(b"account", 45, false, false)
            .await
    );
    assert_eq!(accept_calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn authentication_exchange_switches_to_the_account_plugin_once() {
    let shim = auth_shim("mysql_native_password", false);
    let calls = Arc::clone(&shim.authenticate_calls);
    let input = framed(2, b"switched");
    let mut intermediary = auth_intermediary(shim, &input, false);
    let result = intermediary
        .authenticate_exchange(
            b"next_user",
            45,
            false,
            Some("wrong_plugin"),
            b"salt",
            b"ignored",
            0,
        )
        .await
        .unwrap();
    assert_eq!(result, (true, 2, true));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn matching_plugin_empty_response_is_a_complete_failed_attempt() {
    let shim = auth_shim("mysql_native_password", false);
    let calls = Arc::clone(&shim.authenticate_calls);
    let mut intermediary = auth_intermediary(shim, &[], true);
    assert_eq!(
        intermediary
            .authenticate_exchange(
                b"password_account",
                45,
                false,
                Some("mysql_native_password"),
                b"salt",
                b"",
                0,
            )
            .await
            .unwrap(),
        (false, 0, false)
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn caching_sha2_exchange_has_distinct_fast_and_tls_full_paths() {
    let mut empty = auth_shim("caching_sha2_password", false);
    empty.empty_password = true;
    let mut intermediary = auth_intermediary(empty, &[], false);
    assert_eq!(
        intermediary
            .authenticate_exchange(
                b"next_user",
                45,
                false,
                Some("caching_sha2_password"),
                b"salt",
                b"\0",
                0,
            )
            .await
            .unwrap(),
        (true, 0, false)
    );

    let fast = auth_shim("caching_sha2_password", false);
    let fast_calls = Arc::clone(&fast.authenticate_calls);
    let mut intermediary = auth_intermediary(fast, &[], false);
    assert_eq!(
        intermediary
            .authenticate_exchange(
                b"next_user",
                45,
                false,
                Some("caching_sha2_password"),
                b"salt",
                b"fast",
                0,
            )
            .await
            .unwrap(),
        (true, 1, true)
    );
    assert_eq!(fast_calls.load(Ordering::Relaxed), 1);

    let omitted = auth_shim("caching_sha2_password", false);
    let omitted_calls = Arc::clone(&omitted.authenticate_calls);
    let input = framed(2, b"fast");
    let mut intermediary = auth_intermediary(omitted, &input, true);
    assert_eq!(
        intermediary
            .authenticate_exchange(
                b"next_user",
                45,
                false,
                Some("caching_sha2_password"),
                b"salt",
                b"",
                0,
            )
            .await
            .unwrap(),
        (true, 3, true)
    );
    assert_eq!(omitted_calls.load(Ordering::Relaxed), 2);

    let rejected = auth_shim("caching_sha2_password", false);
    let rejected_calls = Arc::clone(&rejected.authenticate_calls);
    let rejected_cleartext_calls = Arc::clone(&rejected.cleartext_calls);
    let input = framed(2, b"wrong\0");
    let mut intermediary = auth_intermediary(rejected, &input, true);
    assert_eq!(
        intermediary
            .authenticate_exchange(
                b"next_user",
                45,
                false,
                Some("caching_sha2_password"),
                b"salt",
                b"wrong",
                0,
            )
            .await
            .unwrap(),
        (false, 2, true)
    );
    assert_eq!(rejected_calls.load(Ordering::Relaxed), 1);
    assert_eq!(rejected_cleartext_calls.load(Ordering::Relaxed), 1);

    let recovered = auth_shim("caching_sha2_password", false);
    let recovered_calls = Arc::clone(&recovered.authenticate_calls);
    let recovered_cleartext_calls = Arc::clone(&recovered.cleartext_calls);
    let input = framed(2, b"secret\0");
    let mut intermediary = auth_intermediary(recovered, &input, true);
    assert_eq!(
        intermediary
            .authenticate_exchange(
                b"next_user",
                45,
                false,
                Some("caching_sha2_password"),
                b"salt",
                b"cache-miss",
                0,
            )
            .await
            .unwrap(),
        (true, 2, true)
    );
    assert_eq!(recovered_calls.load(Ordering::Relaxed), 1);
    assert_eq!(recovered_cleartext_calls.load(Ordering::Relaxed), 1);

    let full = auth_shim("caching_sha2_password", true);
    let direct_calls = Arc::clone(&full.authenticate_calls);
    let cleartext_calls = Arc::clone(&full.cleartext_calls);
    let input = framed(2, b"secret\0");
    let mut intermediary = auth_intermediary(full, &input, true);
    assert_eq!(
        intermediary
            .authenticate_exchange(
                b"next_user",
                45,
                false,
                Some("caching_sha2_password"),
                b"salt",
                b"cached-response",
                0,
            )
            .await
            .unwrap(),
        (true, 2, true)
    );
    assert_eq!(direct_calls.load(Ordering::Relaxed), 0);
    assert_eq!(cleartext_calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn empty_sha2_password_distinguishes_handshake_proof_from_change_user_probe() {
    for force_full in [false, true] {
        let mut handshake = auth_shim("caching_sha2_password", force_full);
        handshake.empty_password = true;
        let calls = Arc::clone(&handshake.authenticate_calls);
        let mut intermediary = auth_intermediary(handshake, &[], false);
        assert_eq!(
            intermediary
                .authenticate_exchange(
                    b"account",
                    45,
                    true,
                    Some("caching_sha2_password"),
                    b"salt",
                    &[0],
                    0,
                )
                .await
                .unwrap(),
            (true, 0, false),
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        // libmysqlclient starts COM_CHANGE_USER by sending a zero-length
        // probe, even when the caller supplied a password.  The server must
        // request a fresh proof before it can decide that an empty-password
        // account authenticated successfully.
        let mut change_user = auth_shim("caching_sha2_password", force_full);
        change_user.empty_password = true;
        let calls = Arc::clone(&change_user.authenticate_calls);
        let input = framed(2, &[0]);
        let mut intermediary = auth_intermediary(change_user, &input, false);
        assert_eq!(
            intermediary
                .authenticate_exchange(
                    b"account",
                    45,
                    false,
                    Some("caching_sha2_password"),
                    b"salt",
                    b"",
                    0,
                )
                .await
                .unwrap(),
            (true, 2, false),
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }
    let mut intermediary = auth_intermediary(auth_shim("caching_sha2_password", false), &[], false);
    assert_eq!(
        intermediary
            .authenticate_exchange(
                b"account",
                45,
                false,
                Some("caching_sha2_password"),
                b"salt",
                &[0],
                0,
            )
            .await
            .unwrap(),
        (false, 0, false),
    );
}

#[tokio::test]
async fn change_user_probe_never_accepts_a_wrong_password_for_an_empty_password_account() {
    let mut shim = auth_shim("caching_sha2_password", false);
    shim.empty_password = true;
    let authenticate_calls = Arc::clone(&shim.authenticate_calls);
    let cleartext_calls = Arc::clone(&shim.cleartext_calls);
    let mut input = framed(2, b"wrong-fast-proof");
    input.extend_from_slice(&framed(4, b"wrong\0"));
    let mut intermediary = auth_intermediary(shim, &input, true);

    assert_eq!(
        intermediary
            .authenticate_exchange(
                b"empty_password_account",
                45,
                false,
                Some("caching_sha2_password"),
                b"salt",
                b"",
                0,
            )
            .await
            .unwrap(),
        (false, 4, true),
    );
    assert_eq!(authenticate_calls.load(Ordering::Relaxed), 2);
    assert_eq!(cleartext_calls.load(Ordering::Relaxed), 1);
}
