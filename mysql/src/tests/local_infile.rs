use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use mysql_common::constants::CapabilityFlags;
use tokio::io::AsyncWrite;

use crate::packet_reader::PacketReader;
use crate::packet_writer::PacketWriter;
use crate::{
    AsyncMysqlIntermediary, AsyncMysqlShim, LocalInfilePreflight, ParamParser, QueryResultWriter,
    StatementMetaWriter,
};

#[derive(Clone, Default)]
struct LocalInfileShim {
    commands_received: usize,
    starts: Arc<AtomicUsize>,
    data_packets: Arc<AtomicUsize>,
    aborts: Arc<AtomicUsize>,
    ends: Arc<AtomicUsize>,
    cancelled: Arc<AtomicUsize>,
    preflight_drops: Arc<AtomicUsize>,
    sources: Arc<Mutex<Vec<Vec<u8>>>>,
    ordinary: bool,
    reject: bool,
    blocked: bool,
    blocked_finish: bool,
    finish_drops: Arc<AtomicUsize>,
    prepared_executions: Arc<AtomicUsize>,
    filename: Option<Vec<u8>>,
}

#[async_trait]
impl<W: AsyncWrite + Unpin + Send> AsyncMysqlShim<W> for LocalInfileShim {
    type Error = io::Error;

    fn on_command_received(&mut self, _opcode: u8) -> Result<(), Self::Error> {
        self.commands_received += 1;
        Ok(())
    }

    fn max_allowed_packet(&self) -> usize {
        128
    }

    async fn on_prepare<'a>(
        &'a mut self,
        query: &'a [u8],
        info: StatementMetaWriter<'a, W>,
    ) -> Result<(), Self::Error> {
        self.sources.lock().unwrap().push(query.to_vec());
        info.reply(1, &[], &[]).await
    }

    async fn on_execute<'a>(
        &'a mut self,
        _id: u32,
        params: ParamParser<'a>,
        results: QueryResultWriter<'a, W>,
    ) -> Result<(), Self::Error> {
        assert!(params.parse()?.is_empty());
        self.prepared_executions.fetch_add(1, Ordering::Relaxed);
        results.completed(crate::OkResponse::default()).await
    }

    async fn on_close<'a>(&'a mut self, _stmt: u32) {}

    async fn on_query<'a>(
        &'a mut self,
        query: &'a [u8],
        results: QueryResultWriter<'a, W>,
    ) -> Result<(), Self::Error> {
        self.sources.lock().unwrap().push(query.to_vec());
        results.completed(crate::OkResponse::default()).await
    }

    async fn preflight_local_infile<'writer>(
        &mut self,
        query: &[u8],
        client_supports_local: bool,
        results: QueryResultWriter<'writer, W>,
    ) -> Result<LocalInfilePreflight<'writer, W>, Self::Error> {
        if self.ordinary {
            return Ok(LocalInfilePreflight::Continue(results));
        }
        self.sources.lock().unwrap().push(query.to_vec());
        if self.blocked {
            struct PendingAdmission(Arc<AtomicUsize>);
            impl Drop for PendingAdmission {
                fn drop(&mut self) {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
            }
            let _admission = PendingAdmission(Arc::clone(&self.preflight_drops));
            std::future::pending::<()>().await;
        }
        if self.reject || !client_supports_local {
            results
                .error(
                    crate::ErrorKind::ER_TABLEACCESS_DENIED_ERROR,
                    b"preflight denied",
                )
                .await?;
            return Ok(LocalInfilePreflight::Completed);
        }
        self.starts.fetch_add(1, Ordering::Relaxed);
        Ok(LocalInfilePreflight::Request {
            filename: self.filename.as_deref().unwrap_or(b"rows.tsv").to_vec(),
            results,
        })
    }

    async fn on_local_infile_data<'a>(&'a mut self, _data: &'a [u8]) -> Result<(), Self::Error> {
        self.data_packets.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn on_local_infile_abort(&mut self) -> Result<(), Self::Error> {
        self.aborts.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn on_local_infile_end<'a>(
        &'a mut self,
        results: QueryResultWriter<'a, W>,
    ) -> Result<(), Self::Error> {
        self.ends.fetch_add(1, Ordering::Relaxed);
        if self.blocked_finish {
            struct PendingFinish(Arc<AtomicUsize>);
            impl Drop for PendingFinish {
                fn drop(&mut self) {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
            }
            let _finish = PendingFinish(Arc::clone(&self.finish_drops));
            std::future::pending::<()>().await;
        }
        results.completed(crate::OkResponse::default()).await
    }

    async fn on_query_cancelled(&mut self) -> Result<(), Self::Error> {
        self.cancelled.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[tokio::test]
async fn excluded_bug17667_text_and_prepared_sources_preserve_all_native_nul_lengths() {
    // Fixed mysql_client_test.cc14933-14951. The six-NUL PS passes50
    // bytes: its final C string terminator is part of that actual request.
    let statements: &[(bool, &[u8], usize)] = &[
        (false, b"drop table if exists bug17667", 29),
        (false, b"create table bug17667 (c varchar(20))", 37),
        (
            false,
            b"insert into bug17667 (c) values ('regular') /* NUL=\0 with comment */",
            68,
        ),
        (
            true,
            b"insert into bug17667 (c) values ('prepared') /* NUL=\0 with comment */",
            69,
        ),
        (
            false,
            b"insert into bug17667 (c) values ('NUL=\0 in value')",
            50,
        ),
        (
            false,
            b"insert into bug17667 (c) values ('5 NULs=\0\0\0\0\0')",
            48,
        ),
        (
            true,
            b"insert into bug17667 (c) values ('6 NULs=\0\0\0\0\0\0')\0",
            50,
        ),
        (
            false,
            b"/* NUL=\0 with comment */ insert into bug17667 (c) values ('encore')",
            67,
        ),
        (false, b"drop table bug17667", 19),
    ];
    let shim = LocalInfileShim {
        ordinary: true,
        ..Default::default()
    };
    let sources = Arc::clone(&shim.sources);
    let executions = Arc::clone(&shim.prepared_executions);
    let mut input = Vec::new();
    for &(prepared, sql, length) in statements {
        assert_eq!(sql.len(), length, "native explicit byte length");
        input.extend(framed(
            0,
            &[&[if prepared { 0x16 } else { 3 }][..], sql].concat(),
        ));
        if prepared {
            input.extend(framed(0, &[0x17, 1, 0, 0, 0, 0, 1, 0, 0, 0]));
            input.extend(framed(0, &[0x19, 1, 0, 0, 0]));
        }
    }
    let mut output = Vec::new();
    {
        let mut intermediary = AsyncMysqlIntermediary {
            client_capabilities: CapabilityFlags::CLIENT_PROTOCOL_41,
            process_use_statement_on_query: false,
            reject_connection_on_dbname_absence: false,
            shim,
            reader: PacketReader::new(input.as_slice()),
            writer: PacketWriter::new(&mut output),
            zstd_compression_level: 0,
            secure_transport: false,
            uncompressed_allowed: true,
        };
        intermediary.run_commands().await.unwrap();
    }
    assert_eq!(
        *sources.lock().unwrap(),
        statements
            .iter()
            .map(|(_, sql, _)| sql.to_vec())
            .collect::<Vec<_>>()
    );
    assert_eq!(executions.load(Ordering::Relaxed), 2);
    let mut packets = PacketReader::new(output.as_slice());
    let mut completions = 0;
    while let Some((sequence, response)) = packets.next_async().await.unwrap() {
        assert_eq!(sequence, 1);
        assert_eq!(
            response[0], 0,
            "real callback completion, never transport ERR"
        );
        completions += 1;
    }
    assert_eq!(completions, statements.len() + 2);
    // This is transport/backend-byte proof, not SQL parsing or log-file proof.
}

#[tokio::test]
async fn query_and_prepare_reach_the_backend_as_the_exact_packet_bytes() {
    let shim = LocalInfileShim {
        ordinary: true,
        ..Default::default()
    };
    let sources = Arc::clone(&shim.sources);
    let source = b"SELECT '\xff\0\x81\\' /* unchanged */";
    let mut input = framed(0, &[&[3][..], source].concat());
    input.extend(framed(0, &[&[0x16][..], source].concat()));
    let mut intermediary = AsyncMysqlIntermediary {
        client_capabilities: CapabilityFlags::empty(),
        process_use_statement_on_query: true,
        reject_connection_on_dbname_absence: false,
        shim,
        reader: PacketReader::new(input.as_slice()),
        writer: PacketWriter::new(tokio::io::sink()),
        zstd_compression_level: 0,
        secure_transport: false,
        uncompressed_allowed: true,
    };
    intermediary.run_commands().await.unwrap();
    assert_eq!(
        sources.lock().unwrap().as_slice(),
        &[source.to_vec(), source.to_vec()]
    );
    assert_eq!(intermediary.shim.commands_received, 2);
}

#[tokio::test]
async fn local_preflight_error_and_disabled_capability_never_send_a_filename_request() {
    for (capabilities, reject) in [
        (CapabilityFlags::CLIENT_LOCAL_FILES, true),
        (CapabilityFlags::empty(), false),
    ] {
        let shim = LocalInfileShim {
            reject,
            ..Default::default()
        };
        let starts = Arc::clone(&shim.starts);
        let ends = Arc::clone(&shim.ends);
        let sources = Arc::clone(&shim.sources);
        let source = b"LOAD DATA LOCAL INFILE 'rows.tsv' INTO TABLE rows";
        let mut input = framed(0, &[&[3][..], source].concat());
        input.extend(framed(0, &[0x0e]));
        let mut output = Vec::new();
        {
            let mut intermediary = AsyncMysqlIntermediary {
                client_capabilities: capabilities,
                process_use_statement_on_query: true,
                reject_connection_on_dbname_absence: false,
                shim,
                reader: PacketReader::new(input.as_slice()),
                writer: PacketWriter::new(&mut output),
                zstd_compression_level: 0,
                secure_transport: false,
                uncompressed_allowed: true,
            };
            intermediary.run_commands().await.unwrap();
            assert_eq!(intermediary.shim.commands_received, 2);
        }
        assert_eq!(sources.lock().unwrap().as_slice(), &[source.to_vec()]);
        assert_eq!(starts.load(Ordering::Relaxed), 0);
        assert_eq!(ends.load(Ordering::Relaxed), 0);
        let mut packets = PacketReader::new(output.as_slice());
        let (sequence, error) = packets.next_async().await.unwrap().unwrap();
        assert_eq!(sequence, 1);
        assert_eq!(&error[..3], &[0xff, 0x76, 0x04]);
        assert_eq!(&error[3..], b"#42000preflight denied");
        let (_, ping) = packets.next_async().await.unwrap().unwrap();
        assert_eq!(ping[0], 0);
        assert!(packets.next_async().await.unwrap().is_none());
    }
}

#[tokio::test]
async fn eof_drops_the_actual_pending_preflight_before_cancel_without_sending_0xfb() {
    let shim = LocalInfileShim {
        blocked: true,
        ..Default::default()
    };
    let cancelled = Arc::clone(&shim.cancelled);
    let drops = Arc::clone(&shim.preflight_drops);
    let starts = Arc::clone(&shim.starts);
    let input = framed(0, b"\x03LOAD DATA LOCAL INFILE 'rows.tsv' INTO TABLE rows");
    let mut output = Vec::new();
    {
        let mut intermediary = AsyncMysqlIntermediary {
            client_capabilities: CapabilityFlags::CLIENT_LOCAL_FILES,
            process_use_statement_on_query: true,
            reject_connection_on_dbname_absence: false,
            shim,
            reader: PacketReader::new(input.as_slice()),
            writer: PacketWriter::new(&mut output),
            zstd_compression_level: 0,
            secure_transport: false,
            uncompressed_allowed: true,
        };
        let error = intermediary.run_commands().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }
    assert!(output.is_empty());
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(cancelled.load(Ordering::Relaxed), 1);
    assert_eq!(starts.load(Ordering::Relaxed), 0);
}

fn framed(seq: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = payload.len().to_le_bytes()[..3].to_vec();
    frame.push(seq);
    frame.extend_from_slice(payload);
    frame
}

#[tokio::test]
async fn local_upload_keeps_its_exchange_and_following_command_restarts_both_counters() {
    fn envelope(sequence: u8, payload: &[u8]) -> Vec<u8> {
        let mut output = payload.len().to_le_bytes()[..3].to_vec();
        output.push(sequence);
        output.extend_from_slice(&[0; 3]);
        output.extend_from_slice(payload);
        output
    }
    for compression in [0u8, 1, 2] {
        for valid in [true, false] {
            let shim = LocalInfileShim::default();
            let data = shim.data_packets.clone();
            let ends = shim.ends.clone();
            let aborts = shim.aborts.clone();
            let command = framed(0, b"\x03LOAD DATA LOCAL INFILE 'rows.tsv' INTO TABLE rows");
            let upload_sequence = if valid { 2 } else { 0 };
            let upload = framed(upload_sequence, b"7\n");
            let terminal = framed(3, b"");
            let ping = framed(0, &[0x0e]);
            let mut input = Vec::new();
            for (sequence, payload) in [(0, command), (2, upload), (3, terminal), (0, ping)] {
                input.extend(if compression == 0 {
                    payload
                } else {
                    envelope(sequence, &payload)
                });
            }
            let mut output = Vec::new();
            let mut reader = PacketReader::new(input.as_slice());
            let mut writer = PacketWriter::new(&mut output);
            if compression == 1 {
                reader.enable_compression();
                writer.enable_compression();
            } else if compression == 2 {
                reader.enable_zstd_compression();
                writer.enable_zstd_compression(3);
            }
            let mut intermediary = AsyncMysqlIntermediary {
                client_capabilities: CapabilityFlags::CLIENT_LOCAL_FILES,
                process_use_statement_on_query: true,
                reject_connection_on_dbname_absence: false,
                shim,
                reader,
                writer,
                zstd_compression_level: 3,
                secure_transport: false,
                uncompressed_allowed: true,
            };
            let result = intermediary.run_commands().await;
            if valid {
                result.unwrap();
                assert_eq!(intermediary.shim.commands_received, 2);
                assert_eq!(data.load(Ordering::Relaxed), 1);
                assert_eq!(ends.load(Ordering::Relaxed), 1);
                assert_eq!(aborts.load(Ordering::Relaxed), 0);
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert_eq!(
                    error.to_string(),
                    "MySQL packet out of order: received 0, expected 2"
                );
                assert_eq!(data.load(Ordering::Relaxed), 0);
                assert_eq!(ends.load(Ordering::Relaxed), 0);
                assert_eq!(aborts.load(Ordering::Relaxed), 1);
            }
            drop(intermediary);
            let mut packets = PacketReader::new(output.as_slice());
            if compression == 1 {
                packets.enable_compression();
            } else if compression == 2 {
                packets.enable_zstd_compression();
            }
            packets.set_compressed_sequence(1);
            let (sequence, request) = packets.next_async_in_exchange(1).await.unwrap().unwrap();
            assert_eq!(sequence, 1);
            assert_eq!(request.as_ref(), b"\xfbrows.tsv");
            if valid {
                packets.set_compressed_sequence(4);
                let (_, completion) = packets.next_async_in_exchange(4).await.unwrap().unwrap();
                assert_eq!(completion[0], 0);
                packets.set_compressed_sequence(1);
                let (_, ping) = packets.next_async_in_exchange(1).await.unwrap().unwrap();
                assert_eq!(ping[0], 0);
            }
            assert!(packets.next_async().await.unwrap().is_none());
        }
    }
}

#[tokio::test]
async fn eof_drops_actual_local_execution_after_data_without_publishing_a_completion() {
    let shim = LocalInfileShim {
        blocked_finish: true,
        ..Default::default()
    };
    let cancelled = Arc::clone(&shim.cancelled);
    let drops = Arc::clone(&shim.finish_drops);
    let ends = Arc::clone(&shim.ends);
    let mut input = framed(0, b"\x03LOAD DATA LOCAL INFILE 'rows.tsv' INTO TABLE rows");
    input.extend(framed(2, b"7\n"));
    input.extend(framed(3, b""));
    let mut output = Vec::new();
    {
        let mut intermediary = AsyncMysqlIntermediary {
            client_capabilities: CapabilityFlags::CLIENT_LOCAL_FILES,
            process_use_statement_on_query: true,
            reject_connection_on_dbname_absence: false,
            shim,
            reader: PacketReader::new(input.as_slice()),
            writer: PacketWriter::new(&mut output),
            zstd_compression_level: 0,
            secure_transport: false,
            uncompressed_allowed: true,
        };
        let error = intermediary.run_commands().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }
    assert_eq!(ends.load(Ordering::Relaxed), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(cancelled.load(Ordering::Relaxed), 1);
    assert_eq!(output, framed(1, b"\xfbrows.tsv"));
}

#[tokio::test]
async fn oversized_local_infile_is_drained_and_the_next_command_is_read() {
    let shim = LocalInfileShim::default();
    let starts = Arc::clone(&shim.starts);
    let data_packets = Arc::clone(&shim.data_packets);
    let aborts = Arc::clone(&shim.aborts);
    let ends = Arc::clone(&shim.ends);

    let mut query = vec![0x03];
    query.extend_from_slice(b"LOAD DATA LOCAL INFILE 'rows.tsv' INTO TABLE rows");
    let mut input = framed(0, &query);
    input.extend(framed(2, &[b'a'; 80]));
    input.extend(framed(3, &[b'b'; 80]));
    input.extend(framed(4, &[]));
    input.extend(framed(0, &[0x0e]));

    let mut intermediary = AsyncMysqlIntermediary {
        client_capabilities: CapabilityFlags::CLIENT_LOCAL_FILES,
        process_use_statement_on_query: false,
        reject_connection_on_dbname_absence: false,
        shim,
        reader: PacketReader::new(input.as_slice()),
        writer: PacketWriter::new(tokio::io::sink()),
        zstd_compression_level: 0,
        secure_transport: false,
        uncompressed_allowed: true,
    };

    intermediary.run_commands().await.unwrap();
    assert_eq!(
        intermediary.shim.commands_received, 2,
        "PING was read after the drain"
    );
    assert_eq!(starts.load(Ordering::Relaxed), 1);
    assert_eq!(data_packets.load(Ordering::Relaxed), 1);
    assert_eq!(aborts.load(Ordering::Relaxed), 1);
    assert_eq!(ends.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn local_filename_request_transports_non_utf8_octets_and_preserves_exchange_sequence() {
    let filename = b"raw\xff\x81\xca\xee\xf9\xfa\x54.tsv";
    let shim = LocalInfileShim {
        filename: Some(filename.to_vec()),
        ..Default::default()
    };
    let sources = Arc::clone(&shim.sources);
    let ends = Arc::clone(&shim.ends);
    let data = Arc::clone(&shim.data_packets);
    let query = b"LOAD DATA LOCAL INFILE 'raw\xff' INTO TABLE rows";
    let mut input = framed(0, &[&[3][..], query].concat());
    input.extend(framed(2, b"7\n"));
    input.extend(framed(3, b""));
    input.extend(framed(0, &[0x0e]));
    let mut output = Vec::new();
    {
        let mut intermediary = AsyncMysqlIntermediary {
            client_capabilities: CapabilityFlags::CLIENT_LOCAL_FILES,
            process_use_statement_on_query: true,
            reject_connection_on_dbname_absence: false,
            shim,
            reader: PacketReader::new(input.as_slice()),
            writer: PacketWriter::new(&mut output),
            zstd_compression_level: 0,
            secure_transport: false,
            uncompressed_allowed: true,
        };
        intermediary.run_commands().await.unwrap();
        assert_eq!(intermediary.shim.commands_received, 2);
    }
    let mut packets = PacketReader::new(output.as_slice());
    let (sequence, request) = packets.next_async().await.unwrap().unwrap();
    assert_eq!(sequence, 1);
    assert_eq!(
        request.as_ref(),
        [&[0xfb][..], filename].concat().as_slice()
    );
    let (sequence, completed) = packets.next_async().await.unwrap().unwrap();
    assert_eq!(sequence, 4);
    assert_eq!(completed[0], 0);
    let (sequence, ping) = packets.next_async().await.unwrap().unwrap();
    assert_eq!(sequence, 1);
    assert_eq!(ping[0], 0);
    assert!(packets.next_async().await.unwrap().is_none());
    assert_eq!(sources.lock().unwrap().as_slice(), &[query.to_vec()]);
    assert_eq!(data.load(Ordering::Relaxed), 1);
    assert_eq!(ends.load(Ordering::Relaxed), 1);
}
