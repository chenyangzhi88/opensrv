// Copyright 2021 Datafuse Labs.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use mysql_common::constants::{CapabilityFlags, ColumnFlags, ColumnType, StatusFlags};
use tokio::io::AsyncReadExt;

use crate::packet_writer::PacketWriter;
use crate::{Column, OkResponse, QueryResultWriter};

fn progress_column() -> Column {
    Column {
        database: Vec::new(),
        table: Vec::new(),
        org_table: Vec::new(),
        column: b"progress".to_vec(),
        org_column: Vec::new(),
        collen: 11,
        charset: Some(63),
        coltype: ColumnType::MYSQL_TYPE_LONG,
        colflags: ColumnFlags::BINARY_FLAG,
        decimals: None,
    }
}

#[tokio::test]
async fn prepare_parameter_count_cannot_wrap_and_publish_a_false_statement_signature() {
    let column = progress_column();
    let parameters = vec![&column; 65536];
    let mut statements = std::collections::HashMap::new();
    let mut output = Vec::new();
    {
        let mut writer = PacketWriter::new(&mut output);
        crate::StatementMetaWriter {
            writer: &mut writer,
            stmts: &mut statements,
            client_capabilities: CapabilityFlags::CLIENT_PROTOCOL_41,
        }
        .reply(99, parameters, &[])
        .await
        .unwrap();
        writer.flush_all().await.unwrap();
    }
    assert!(!statements.contains_key(&99));
    let mut reader = crate::packet_reader::PacketReader::new(output.as_slice());
    let (_, packet) = reader.next_async().await.unwrap().unwrap();
    assert_eq!(
        &packet[..],
        b"\xff\x6e\x05#HY000Prepared statement contains too many placeholders"
    );
    assert!(reader.next_async().await.unwrap().is_none());
}

#[derive(Default)]
struct ProgressState {
    buffered: Vec<u8>,
    visible: Vec<u8>,
    flushes: usize,
    shutdowns: usize,
    block_flush: bool,
    flush_error: Option<std::io::ErrorKind>,
    write_error: Option<std::io::ErrorKind>,
    write_limit: Option<usize>,
}

struct ProgressWriter(std::sync::Arc<std::sync::Mutex<ProgressState>>);

impl tokio::io::AsyncWrite for ProgressWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let mut state = self.0.lock().unwrap();
        if let Some(kind) = state.write_error {
            return std::task::Poll::Ready(Err(kind.into()));
        }
        let length = state.write_limit.unwrap_or(bytes.len()).min(bytes.len());
        if length == 0 {
            return std::task::Poll::Pending;
        }
        state.buffered.extend_from_slice(&bytes[..length]);
        context.waker().wake_by_ref();
        std::task::Poll::Ready(Ok(length))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut state = self.0.lock().unwrap();
        if state.block_flush {
            return std::task::Poll::Pending;
        }
        if let Some(kind) = state.flush_error {
            return std::task::Poll::Ready(Err(kind.into()));
        }
        let mut bytes = std::mem::take(&mut state.buffered);
        state.visible.append(&mut bytes);
        state.flushes += 1;
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.0.lock().unwrap().shutdowns += 1;
        std::task::Poll::Ready(Ok(()))
    }
}

fn visible_packets(state: &std::sync::Mutex<ProgressState>) -> Vec<Vec<u8>> {
    let state = state.lock().unwrap();
    let mut bytes = state.visible.as_slice();
    let mut packets = Vec::new();
    while !bytes.is_empty() {
        assert!(bytes.len() >= 4);
        let length =
            usize::from(bytes[0]) | usize::from(bytes[1]) << 8 | usize::from(bytes[2]) << 16;
        assert!(bytes.len() >= 4 + length);
        assert_eq!(bytes[3], packets.len() as u8);
        packets.push(bytes[4..4 + length].to_vec());
        bytes = &bytes[4 + length..];
    }
    packets
}

// Returning this type proves the local allocation is owned, not stack-borrowed.
async fn locally_owned_rows<'a>(
    packets: &'a mut PacketWriter<ProgressWriter>,
    binary: bool,
    capabilities: CapabilityFlags,
    metadata: bool,
) -> crate::RowWriter<'a, 'static, ProgressWriter> {
    let columns = vec![progress_column()];
    let result = QueryResultWriter::new(packets, binary, capabilities);
    if metadata {
        result.start_owned(columns).await.unwrap()
    } else {
        result.start_without_metadata_owned(columns).await.unwrap()
    }
}

#[tokio::test]
async fn borrowed_and_owned_rows_share_exact_text_binary_and_optional_metadata_packets() {
    for binary in [false, true] {
        for metadata in [false, true] {
            for deprecate_eof in [false, true] {
                let mut capabilities = CapabilityFlags::CLIENT_PROTOCOL_41
                    | CapabilityFlags::CLIENT_OPTIONAL_RESULTSET_METADATA;
                capabilities.set(CapabilityFlags::CLIENT_DEPRECATE_EOF, deprecate_eof);
                let mut outputs = Vec::new();
                for owned in [false, true] {
                    let state = std::sync::Arc::new(std::sync::Mutex::new(ProgressState {
                        write_limit: Some(2),
                        ..Default::default()
                    }));
                    let mut packets = PacketWriter::new(ProgressWriter(state.clone()));
                    let columns = [progress_column()];
                    let mut rows = if owned {
                        locally_owned_rows(&mut packets, binary, capabilities, metadata).await
                    } else {
                        let result = QueryResultWriter::new(&mut packets, binary, capabilities);
                        if metadata {
                            result.start(&columns).await.unwrap()
                        } else {
                            result.start_without_metadata(&columns).await.unwrap()
                        }
                    };
                    assert!(state.lock().unwrap().visible.is_empty());
                    rows.flush_progress().await.unwrap();
                    let prefix = visible_packets(&state);
                    assert_eq!(prefix[0], [1, u8::from(metadata)]);
                    assert_eq!(
                        prefix.len(),
                        1 + usize::from(metadata) * (1 + usize::from(!deprecate_eof))
                    );
                    rows.write_row([7_i32]).await.unwrap();
                    rows.flush_progress().await.unwrap();
                    let progress = visible_packets(&state);
                    assert_eq!(progress.len(), prefix.len() + 1);
                    assert_eq!(
                        progress.last().unwrap(),
                        if binary {
                            &[0, 0, 7, 0, 0, 0][..]
                        } else {
                            &[1, b'7'][..]
                        }
                    );
                    // Progress is not EOF/OK: a second row remains writable on this writer.
                    rows.write_row([8_i32]).await.unwrap();
                    let result = rows
                        .finish_one_with_status_and_warnings(
                            StatusFlags::SERVER_STATUS_IN_TRANS,
                            0,
                            Vec::new(),
                        )
                        .await
                        .unwrap();
                    let result = result.flush_more_results().await.unwrap();
                    let complete = visible_packets(&state);
                    assert_eq!(complete.len(), progress.len() + 2);
                    let terminal = complete.last().unwrap();
                    assert_eq!(terminal[0], 0xfe);
                    let status = if deprecate_eof {
                        ok_status(terminal)
                    } else {
                        StatusFlags::from_bits_truncate(u16::from_le_bytes([
                            terminal[3],
                            terminal[4],
                        ]))
                    };
                    assert!(status.contains(StatusFlags::SERVER_MORE_RESULTS_EXISTS));
                    assert!(status.contains(StatusFlags::SERVER_STATUS_IN_TRANS));
                    result
                        .error_raw(4321, b"45000", &b"late error"[..])
                        .await
                        .unwrap();
                    packets.flush_all().await.unwrap();
                    let final_packets = visible_packets(&state);
                    assert_eq!(final_packets.len(), complete.len() + 1);
                    assert_eq!(
                        &final_packets.last().unwrap()[..9],
                        &[0xff, 0xe1, 0x10, b'#', b'4', b'5', b'0', b'0', b'0']
                    );
                    assert_eq!(state.lock().unwrap().shutdowns, 0);
                    outputs.push(final_packets);
                }
                assert_eq!(outputs[0], outputs[1]);
            }
        }
    }
}

#[tokio::test]
async fn owned_progress_then_row_error_has_no_completion_packet() {
    let state = std::sync::Arc::new(std::sync::Mutex::new(ProgressState::default()));
    let mut packets = PacketWriter::new(ProgressWriter(state.clone()));
    let capabilities = CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_DEPRECATE_EOF;
    let mut rows = locally_owned_rows(&mut packets, false, capabilities, true).await;
    rows.write_row([1_i32]).await.unwrap();
    rows.flush_progress().await.unwrap();
    let prefix = visible_packets(&state);
    assert_eq!(prefix.len(), 3);
    assert_eq!(prefix[2], [1, b'1']);
    rows.finish_error_raw(4321, b"45000", &b"second row failed"[..])
        .await
        .unwrap();
    packets.flush_all().await.unwrap();
    let packets = visible_packets(&state);
    assert_eq!(packets.len(), prefix.len() + 1);
    assert_eq!(packets.last().unwrap()[0], 0xff);
    assert_eq!(&packets[..prefix.len()], prefix);
}

#[tokio::test]
async fn progress_rejects_partial_rows_and_owned_columns_still_validate_binary_nulls() {
    let state = std::sync::Arc::new(std::sync::Mutex::new(ProgressState::default()));
    let mut packets = PacketWriter::new(ProgressWriter(state.clone()));
    let capabilities = CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_DEPRECATE_EOF;
    let mut rows = locally_owned_rows(&mut packets, true, capabilities, true).await;
    rows.write_col(9_i32).unwrap();
    assert_eq!(
        rows.flush_progress().await.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(state.lock().unwrap().flushes, 0);
    assert!(state.lock().unwrap().visible.is_empty());
    rows.end_row().await.unwrap();
    rows.flush_progress().await.unwrap();
    assert_eq!(visible_packets(&state).len(), 3);
    // Drop an open response: it does not manufacture EOF/OK in Drop.
    drop(rows);
    assert_eq!(visible_packets(&state).len(), 3);
    let mut column = progress_column();
    column.colflags.insert(ColumnFlags::NOT_NULL_FLAG);
    let mut rows = QueryResultWriter::new(&mut packets, true, capabilities)
        .start_owned(vec![column])
        .await
        .unwrap();
    assert_eq!(
        rows.write_col(None::<i32>).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    drop(rows);
}

#[tokio::test]
async fn progress_flush_backpressure_and_transport_errors_never_finalize_a_rowset() {
    use std::future::Future;
    for failure in [None, Some(std::io::ErrorKind::ConnectionReset)] {
        let state = std::sync::Arc::new(std::sync::Mutex::new(ProgressState::default()));
        let mut packets = PacketWriter::new(ProgressWriter(state.clone()));
        let mut rows = locally_owned_rows(
            &mut packets,
            false,
            CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_DEPRECATE_EOF,
            true,
        )
        .await;
        rows.write_row([1_i32]).await.unwrap();
        state.lock().unwrap().block_flush = true;
        let mut future = Box::pin(rows.flush_progress());
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        assert!(future.as_mut().poll(&mut context).is_pending());
        assert!(state.lock().unwrap().visible.is_empty());
        {
            let mut state = state.lock().unwrap();
            state.block_flush = false;
            state.flush_error = failure;
        }
        match failure {
            None => {
                future.await.unwrap();
                assert_eq!(visible_packets(&state).len(), 3);
            }
            Some(kind) => {
                assert_eq!(future.await.unwrap_err().kind(), kind);
                assert!(state.lock().unwrap().visible.is_empty());
            }
        }
        drop(rows);
        assert_eq!(state.lock().unwrap().shutdowns, 0);
        assert_eq!(
            state.lock().unwrap().flushes,
            usize::from(failure.is_none())
        );
    }
    let state = std::sync::Arc::new(std::sync::Mutex::new(ProgressState {
        write_error: Some(std::io::ErrorKind::BrokenPipe),
        ..Default::default()
    }));
    let mut packets = PacketWriter::new(ProgressWriter(state.clone()));
    let error =
        match QueryResultWriter::new(&mut packets, false, CapabilityFlags::CLIENT_PROTOCOL_41)
            .start_owned(vec![progress_column()])
            .await
        {
            Ok(_) => panic!("metadata write must fail"),
            Err(error) => error,
        };
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    assert!(state.lock().unwrap().visible.is_empty());
}

#[tokio::test]
async fn empty_owned_columns_and_cancelled_flush_do_not_synthesize_success() {
    use std::future::Future;
    let state = std::sync::Arc::new(std::sync::Mutex::new(ProgressState::default()));
    let mut packets = PacketWriter::new(ProgressWriter(state.clone()));
    let mut rows = QueryResultWriter::new(&mut packets, false, CapabilityFlags::CLIENT_PROTOCOL_41)
        .start_owned(Vec::new())
        .await
        .unwrap();
    rows.write_row([1_i32]).await.unwrap();
    rows.flush_progress().await.unwrap();
    assert!(visible_packets(&state).is_empty());
    drop(rows);
    let mut rows = locally_owned_rows(
        &mut packets,
        false,
        CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_DEPRECATE_EOF,
        true,
    )
    .await;
    rows.write_row([1_i32]).await.unwrap();
    state.lock().unwrap().block_flush = true;
    let mut future = Box::pin(rows.flush_progress());
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    assert!(future.as_mut().poll(&mut context).is_pending());
    drop(future);
    drop(rows);
    assert!(visible_packets(&state).is_empty());
    let state = state.lock().unwrap();
    assert_eq!(state.flushes, 1);
    assert_eq!(state.shutdowns, 0);
    // The caller must close an abandoned transport; dropping RowWriter does
    // not perform IO or pretend that these buffered packets completed CALL.
}

#[tokio::test]
async fn selected_handler_boundary_is_exact_legacy_eof_with_or_without_deprecate_eof() {
    for binary in [false, true] {
        for owned in [false, true] {
            for metadata in [false, true] {
                for deprecate_eof in [false, true] {
                    let state = std::sync::Arc::new(std::sync::Mutex::new(ProgressState {
                        write_limit: Some(2),
                        ..Default::default()
                    }));
                    let mut packets = PacketWriter::new(ProgressWriter(state.clone()));
                    let mut capabilities = CapabilityFlags::CLIENT_PROTOCOL_41
                        | CapabilityFlags::CLIENT_OPTIONAL_RESULTSET_METADATA
                        | CapabilityFlags::CLIENT_SESSION_TRACK;
                    capabilities.set(CapabilityFlags::CLIENT_DEPRECATE_EOF, deprecate_eof);
                    let columns = [progress_column()];
                    let mut rows = if owned {
                        locally_owned_rows(&mut packets, binary, capabilities, metadata).await
                    } else {
                        let result = QueryResultWriter::new(&mut packets, binary, capabilities);
                        if metadata {
                            result.start(&columns).await.unwrap()
                        } else {
                            result.start_without_metadata(&columns).await.unwrap()
                        }
                    };
                    rows.write_row([1_i32]).await.unwrap();
                    rows.flush_progress().await.unwrap();
                    let prefix = visible_packets(&state);
                    assert_eq!(
                        prefix.last().unwrap(),
                        if binary {
                            &[0, 0, 1, 0, 0, 0][..]
                        } else {
                            &[1, b'1'][..]
                        }
                    );
                    let status = StatusFlags::SERVER_STATUS_AUTOCOMMIT
                        | StatusFlags::SERVER_MORE_RESULTS_EXISTS;
                    let result = rows.finish_handled_partial(status).await.unwrap();
                    let handled = visible_packets(&state);
                    assert_eq!(handled.len(), prefix.len() + 1);
                    assert_eq!(&handled[..prefix.len()], prefix);
                    // Native selected-handler packet, not a deprecate-EOF FE-OK.
                    assert_eq!(handled.last().unwrap(), &[0xfe, 0, 0, 0x0a, 0]);
                    assert_eq!(state.lock().unwrap().flushes, 2);
                    assert_eq!(state.lock().unwrap().shutdowns, 0);

                    let mut next = result.start_owned(vec![progress_column()]).await.unwrap();
                    next.write_row([99_i32]).await.unwrap();
                    next.flush_progress().await.unwrap();
                    let next_prefix = visible_packets(&state);
                    assert_eq!(&next_prefix[..handled.len()], handled);
                    assert_eq!(
                        next_prefix.len(),
                        handled.len() + 3 + usize::from(!deprecate_eof)
                    );
                    assert_eq!(
                        next_prefix.last().unwrap(),
                        if binary {
                            &[0, 0, 99, 0, 0, 0][..]
                        } else {
                            &[2, b'9', b'9'][..]
                        }
                    );
                    // Ordinary completion still follows its negotiated policy and
                    // actual warnings; the handler API did not replace that policy.
                    let result = next
                        .finish_one_with_status_and_warnings(
                            StatusFlags::SERVER_STATUS_AUTOCOMMIT,
                            7,
                            Vec::new(),
                        )
                        .await
                        .unwrap()
                        .flush_more_results()
                        .await
                        .unwrap();
                    let completed = visible_packets(&state);
                    assert_eq!(completed.len(), next_prefix.len() + 1);
                    let normal_end = completed.last().unwrap();
                    assert_eq!(normal_end[0], 0xfe);
                    if deprecate_eof {
                        assert!(normal_end.len() >= 7);
                        assert_eq!(u16::from_le_bytes([normal_end[5], normal_end[6]]), 7);
                        assert!(
                            ok_status(normal_end).contains(StatusFlags::SERVER_MORE_RESULTS_EXISTS)
                        );
                    } else {
                        assert_eq!(normal_end, &[0xfe, 7, 0, 0x0a, 0]);
                    }
                    result
                        .completed(OkResponse {
                            status_flags: StatusFlags::SERVER_STATUS_AUTOCOMMIT,
                            ..Default::default()
                        })
                        .await
                        .unwrap();
                    packets.flush_all().await.unwrap();
                    let final_packets = visible_packets(&state);
                    assert_eq!(final_packets.len(), completed.len() + 1);
                    assert_eq!(final_packets.last().unwrap()[0], 0);
                    assert_eq!(&final_packets[..completed.len()], completed);
                    assert_eq!(state.lock().unwrap().shutdowns, 0);
                }
            }
        }
    }
}

#[tokio::test]
async fn selected_handler_boundary_preserves_transport_errors_and_never_returns_a_success_writer() {
    for fail_write in [false, true] {
        let state = std::sync::Arc::new(std::sync::Mutex::new(ProgressState::default()));
        let mut packets = PacketWriter::new(ProgressWriter(state.clone()));
        let mut rows = locally_owned_rows(
            &mut packets,
            false,
            CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_DEPRECATE_EOF,
            true,
        )
        .await;
        rows.write_row([1_i32]).await.unwrap();
        rows.flush_progress().await.unwrap();
        let prefix = visible_packets(&state);
        let expected = if fail_write {
            std::io::ErrorKind::BrokenPipe
        } else {
            std::io::ErrorKind::ConnectionReset
        };
        {
            let mut state = state.lock().unwrap();
            if fail_write {
                state.write_error = Some(expected);
            } else {
                state.flush_error = Some(expected);
            }
        }
        let error = match rows
            .finish_handled_partial(StatusFlags::SERVER_MORE_RESULTS_EXISTS)
            .await
        {
            Ok(_) => panic!("failed physical boundary must not yield a reusable writer"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), expected);
        assert_eq!(visible_packets(&state), prefix);
        assert_eq!(state.lock().unwrap().flushes, 1);
        assert_eq!(state.lock().unwrap().shutdowns, 0);
    }
    let state = std::sync::Arc::new(std::sync::Mutex::new(ProgressState::default()));
    let mut packets = PacketWriter::new(ProgressWriter(state.clone()));
    let mut rows = QueryResultWriter::new(
        &mut packets,
        true,
        CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_DEPRECATE_EOF,
    )
    .start_owned(vec![progress_column(), progress_column()])
    .await
    .unwrap();
    rows.flush_progress().await.unwrap();
    let prefix = visible_packets(&state);
    rows.write_col(1_i32).unwrap();
    let error = match rows
        .finish_handled_partial(StatusFlags::SERVER_MORE_RESULTS_EXISTS)
        .await
    {
        Ok(_) => panic!("an incomplete row must fail before handler EOF"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(visible_packets(&state), prefix);
    assert_eq!(state.lock().unwrap().flushes, 1);
}

#[tokio::test]
async fn selected_handler_boundary_waits_for_real_flush_and_drop_never_adds_io() {
    use std::future::Future;
    for cancel in [false, true] {
        let state = std::sync::Arc::new(std::sync::Mutex::new(ProgressState::default()));
        let mut packets = PacketWriter::new(ProgressWriter(state.clone()));
        let mut rows = locally_owned_rows(
            &mut packets,
            false,
            CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_DEPRECATE_EOF,
            true,
        )
        .await;
        rows.write_row([1_i32]).await.unwrap();
        rows.flush_progress().await.unwrap();
        let prefix = visible_packets(&state);
        state.lock().unwrap().block_flush = true;
        let mut future = Box::pin(rows.finish_handled_partial(
            StatusFlags::SERVER_STATUS_AUTOCOMMIT | StatusFlags::SERVER_MORE_RESULTS_EXISTS,
        ));
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        assert!(future.as_mut().poll(&mut context).is_pending());
        assert_eq!(visible_packets(&state), prefix);
        let buffered = state.lock().unwrap().buffered.clone();
        assert_eq!(&buffered[4..], &[0xfe, 0, 0, 0x0a, 0]);
        if cancel {
            drop(future);
            assert_eq!(visible_packets(&state), prefix);
            assert_eq!(state.lock().unwrap().buffered, buffered);
            assert_eq!(state.lock().unwrap().flushes, 1);
            // The connection owner must close this abandoned transport. Drop
            // cannot issue handler output or turn an unflushed EOF into success.
        } else {
            state.lock().unwrap().block_flush = false;
            let result = future.await.unwrap();
            let handled = visible_packets(&state);
            assert_eq!(handled.len(), prefix.len() + 1);
            assert_eq!(handled.last().unwrap(), &[0xfe, 0, 0, 0x0a, 0]);
            assert_eq!(state.lock().unwrap().flushes, 2);
            drop(result);
            assert_eq!(visible_packets(&state), handled);
        }
        assert_eq!(state.lock().unwrap().shutdowns, 0);
    }
}

async fn read_packet(stream: &mut tokio::io::DuplexStream) -> Vec<u8> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    let length =
        usize::from(header[0]) | usize::from(header[1]) << 8 | usize::from(header[2]) << 16;
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await.unwrap();
    payload
}

fn ok_status(payload: &[u8]) -> StatusFlags {
    // Cursor terminators have two zero length-encoded integers before the
    // status and warning fields.
    StatusFlags::from_bits_truncate(u16::from_le_bytes([payload[3], payload[4]]))
}

#[tokio::test]
async fn cursor_open_ok_preserves_warnings_and_session_state() {
    let capabilities = CapabilityFlags::CLIENT_PROTOCOL_41
        | CapabilityFlags::CLIENT_DEPRECATE_EOF
        | CapabilityFlags::CLIENT_SESSION_TRACK;
    let (mut client, server) = tokio::io::duplex(2048);
    let mut packets = PacketWriter::new(server);
    let columns = [Column {
        database: Vec::new(),
        table: Vec::new(),
        org_table: Vec::new(),
        column: b"value".to_vec(),
        org_column: Vec::new(),
        collen: 11,
        charset: Some(63),
        coltype: ColumnType::MYSQL_TYPE_LONG,
        colflags: ColumnFlags::BINARY_FLAG,
        decimals: None,
    }];
    QueryResultWriter::new(&mut packets, true, capabilities)
        .cursor_open(
            &columns,
            OkResponse {
                status_flags: StatusFlags::SERVER_SESSION_STATE_CHANGED,
                warnings: 2,
                session_state_info: vec![5, 2, 1, b'T'],
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(read_packet(&mut client).await, [1]);
    let _column_definition = read_packet(&mut client).await;
    let payload = read_packet(&mut client).await;
    assert_eq!(payload[0], 0xfe);
    assert!(ok_status(&payload).contains(StatusFlags::SERVER_STATUS_CURSOR_EXISTS));
    assert!(ok_status(&payload).contains(StatusFlags::SERVER_SESSION_STATE_CHANGED));
    assert_eq!(u16::from_le_bytes([payload[5], payload[6]]), 2);
    assert_eq!(&payload[7..], &[0, 4, 5, 2, 1, b'T']);
}

#[tokio::test]
async fn cursor_fetch_ok_preserves_warnings_and_session_state() {
    let capabilities = CapabilityFlags::CLIENT_PROTOCOL_41
        | CapabilityFlags::CLIENT_DEPRECATE_EOF
        | CapabilityFlags::CLIENT_SESSION_TRACK;
    let (mut client, server) = tokio::io::duplex(1024);
    let mut packets = PacketWriter::new(server);
    let response = OkResponse {
        status_flags: StatusFlags::SERVER_STATUS_AUTOCOMMIT
            | StatusFlags::SERVER_SESSION_STATE_CHANGED,
        warnings: 7,
        session_state_info: vec![5, 2, 1, b'I'],
        ..Default::default()
    };
    QueryResultWriter::new(&mut packets, true, capabilities)
        .start_cursor_fetch(&[])
        .await
        .unwrap()
        .finish_cursor(true, response)
        .await
        .unwrap();

    let payload = read_packet(&mut client).await;
    assert_eq!(payload[0], 0xfe);
    assert!(ok_status(&payload).contains(StatusFlags::SERVER_STATUS_LAST_ROW_SENT));
    assert!(ok_status(&payload).contains(StatusFlags::SERVER_SESSION_STATE_CHANGED));
    assert_eq!(u16::from_le_bytes([payload[5], payload[6]]), 7);
    assert_eq!(&payload[7..], &[0, 4, 5, 2, 1, b'I']);
}

#[tokio::test]
async fn legacy_cursor_eof_preserves_status_and_warning_count() {
    let capabilities = CapabilityFlags::CLIENT_PROTOCOL_41;
    let (mut client, server) = tokio::io::duplex(1024);
    let mut packets = PacketWriter::new(server);
    QueryResultWriter::new(&mut packets, true, capabilities)
        .start_cursor_fetch(&[])
        .await
        .unwrap()
        .finish_cursor(
            false,
            OkResponse {
                status_flags: StatusFlags::SERVER_STATUS_IN_TRANS,
                warnings: 3,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let payload = read_packet(&mut client).await;
    assert_eq!(payload[0], 0xfe);
    assert_eq!(u16::from_le_bytes([payload[1], payload[2]]), 3);
    let status = StatusFlags::from_bits_truncate(u16::from_le_bytes([payload[3], payload[4]]));
    assert!(status.contains(StatusFlags::SERVER_STATUS_IN_TRANS));
    assert!(status.contains(StatusFlags::SERVER_STATUS_CURSOR_EXISTS));
}
