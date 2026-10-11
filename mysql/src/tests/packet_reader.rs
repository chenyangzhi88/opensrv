use bytes::{Buf, BufMut, BytesMut};

use crate::U24_MAX;

// A real Pending read wakes only the competing response. The response wins
// select and drops the pending read before this gate is explicitly resumed.
pub(crate) struct PauseAtRead {
    bytes: Vec<u8>,
    offset: usize,
    pause: usize,
    resume: std::sync::Arc<std::sync::atomic::AtomicBool>,
    paused: Option<tokio::sync::oneshot::Sender<()>>,
}

impl PauseAtRead {
    pub(crate) fn new(
        bytes: Vec<u8>,
        pause: usize,
    ) -> (
        Self,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        assert!(pause < bytes.len());
        let resume = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (paused, receiver) = tokio::sync::oneshot::channel();
        (
            Self {
                bytes,
                offset: 0,
                pause,
                resume: resume.clone(),
                paused: Some(paused),
            },
            resume,
            receiver,
        )
    }

    pub(crate) fn consumed(&self) -> usize {
        self.offset
    }
}

impl tokio::io::AsyncRead for PauseAtRead {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let resumed = self.resume.load(std::sync::atomic::Ordering::SeqCst);
        if !resumed && self.offset == self.pause {
            if let Some(paused) = self.paused.take() {
                paused.send(()).unwrap();
            }
            return std::task::Poll::Pending;
        }
        let available = if resumed {
            self.bytes.len()
        } else {
            self.pause
        };
        let length = buffer.remaining().min(available - self.offset);
        buffer.put_slice(&self.bytes[self.offset..self.offset + length]);
        self.offset += length;
        std::task::Poll::Ready(Ok(()))
    }
}

pub(crate) fn compression_frame(sequence: u8, plain: &[u8], zstd: bool) -> Vec<u8> {
    use std::io::Write;
    let body = if zstd {
        zstd::stream::encode_all(plain, 1).unwrap()
    } else {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(plain).unwrap();
        encoder.finish().unwrap()
    };
    let mut frame = body.len().to_le_bytes()[..3].to_vec();
    frame.push(sequence);
    frame.extend_from_slice(&plain.len().to_le_bytes()[..3]);
    frame.extend_from_slice(&body);
    frame
}

#[tokio::test]
async fn pending_plain_read_returns_the_same_prefix_allocation_to_its_reader() {
    for length in 1..7 {
        let input = b"\x03\0\0\0abc\x01\0\0\0z".to_vec();
        let (source, resume, paused) = PauseAtRead::new(input.clone(), length);
        let mut reader = PacketReader::new(source);
        let outcome = crate::poll_command_response(
            &mut reader,
            async {
                paused.await.unwrap();
                Ok::<_, std::io::Error>(7)
            },
            "actual pending plain read",
        )
        .await;
        assert!(matches!(
            outcome,
            crate::CommandResponseOutcome::Completed(Ok(7))
        ));
        assert_eq!(reader.r.consumed(), length);
        assert_eq!(reader.bytes.as_ref(), &input[..length]);
        assert!(reader.new_command_in_progress);
        let pointer = reader.bytes.as_ptr();
        // A second cancelled borrow neither discards nor recopies the prefix.
        let mut pending = Box::pin(reader.next_async_new_command(None));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(pending.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(pending);
        assert_eq!(reader.bytes.as_ref(), &input[..length]);
        assert_eq!(reader.bytes.as_ptr(), pointer);
        resume.store(true, std::sync::atomic::Ordering::SeqCst);
        let (sequence, command) = reader.next_async_new_command(None).await.unwrap().unwrap();
        assert_eq!(sequence, 0);
        assert_eq!(command.as_ref(), b"abc");
        assert!(!reader.new_command_in_progress);
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
        assert!(reader.next_async_new_command(None).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn cancelled_command_peek_yields_to_local_exchange_then_next_command_resets() {
    for algorithm in 0..3 {
        let upload = b"\x03\0\0\x02abc";
        let successor = b"\x01\0\0\0z";
        let input = if algorithm == 0 {
            [upload.as_slice(), successor.as_slice()].concat()
        } else {
            [
                compression_frame(2, upload, algorithm == 2),
                compression_frame(0, successor, algorithm == 2),
            ]
            .concat()
        };
        let (source, resume, paused) = PauseAtRead::new(input, 0);
        let mut reader = PacketReader::new(source);
        if algorithm == 1 {
            reader.enable_compression();
        }
        if algorithm == 2 {
            reader.enable_zstd_compression();
        }
        let outcome = crate::poll_command_response(
            &mut reader,
            async {
                paused.await.unwrap();
                Ok::<_, std::io::Error>(7)
            },
            "actual pending LOCAL admission",
        )
        .await;
        assert!(matches!(
            outcome,
            crate::CommandResponseOutcome::Completed(Ok(7))
        ));
        assert!(reader.new_command_in_progress);
        // Existing LOCAL caller installs its actually emitted writer counter.
        reader.set_compressed_sequence(2);
        resume.store(true, std::sync::atomic::Ordering::SeqCst);
        let (sequence, body) = reader.next_async_in_exchange(2).await.unwrap().unwrap();
        assert_eq!(sequence, 2);
        assert_eq!(body.as_ref(), b"abc");
        assert!(!reader.new_command_in_progress);
        let (sequence, command) = reader.next_async_new_command(None).await.unwrap().unwrap();
        assert_eq!(sequence, 0);
        assert_eq!(command.as_ref(), b"z");
        assert!(reader.next_async_new_command(None).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn compressed_pending_body_commits_sequence_only_with_decoded_bytes_and_wraps() {
    for zstd in [false, true] {
        let frame = compression_frame(255, b"\x03\0\0\xfeabc", zstd);
        for cut in [1, 6, 7, frame.len() - 1] {
            let (source, resume, paused) = PauseAtRead::new(frame.clone(), cut);
            let mut reader = PacketReader::new(source);
            if zstd {
                reader.enable_zstd_compression();
            } else {
                reader.enable_compression();
            }
            reader.set_compressed_sequence(255);
            let response = async {
                paused.await.unwrap();
            };
            tokio::pin!(response);
            tokio::select! {
                biased;
                () = &mut response => {},
                read = reader.next_async_in_exchange(254) => panic!("read must remain pending: {}", read.is_ok()),
            }
            assert_eq!(reader.compressed_bytes.as_ref(), &frame[..cut]);
            assert_eq!(reader.compressed_sequence(), 255);
            assert!(reader.bytes.is_empty());
            resume.store(true, std::sync::atomic::Ordering::SeqCst);
            let (sequence, packet) = reader.next_async_in_exchange(254).await.unwrap().unwrap();
            assert_eq!(sequence, 254);
            assert_eq!(packet.as_ref(), b"abc");
            assert_eq!(reader.compressed_sequence(), 0);
        }
    }
}

#[tokio::test]
async fn exchange_first_sequence_and_new_command_reset_use_actual_fragment_ordinals() {
    for expected in [0u8, 1, 2, 254, 255] {
        let payload = bytes::Bytes::from(vec![9; U24_MAX]);
        let encoded = mock_packet(payload.clone(), expected);
        let mut reader = PacketReader::new(encoded.as_ref());
        let (last, actual) = reader
            .next_async_in_exchange(expected)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(last, expected.wrapping_add(1));
        assert_eq!(actual.as_ref(), payload.as_ref());
        let mut reader = PacketReader::new(encoded.as_ref());
        let error = reader
            .next_async_in_exchange(expected.wrapping_add(1))
            .await
            .err()
            .expect("first sequence");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains(&format!(
            "received {expected}, expected {}",
            expected.wrapping_add(1)
        )));
    }
    let input = b"\x01\0\0\x01z";
    let mut reader = PacketReader::new(&input[..]);
    assert_eq!(
        reader
            .next_async_new_command(None)
            .await
            .err()
            .expect("command sequence zero")
            .kind(),
        std::io::ErrorKind::InvalidData
    );
    let input = b"\x05\0\0\x02\0\0\0\x01\0\0\x02z";
    let mut reader = PacketReader::new(&input[..]);
    reader.enable_compression();
    reader.set_compressed_sequence(2);
    assert_eq!(
        reader
            .next_async_in_exchange(2)
            .await
            .unwrap()
            .unwrap()
            .1
            .as_ref(),
        b"z"
    );
    assert_eq!(reader.compressed_sequence(), 3);
}
use crate::packet_reader::*;

#[tokio::test]
async fn continuation_sequence_wraps_and_bad_sequence_is_an_error_not_a_panic() {
    // One actual 0xffffff continuation exercises both physical header kinds
    // without inventing a smaller production chunk size for the test.
    let payload = bytes::Bytes::from(vec![0x5a; U24_MAX + 3]);
    for first in [254u8, 255] {
        let encoded = mock_packet(payload.clone(), first);
        let (rest, (last, parsed)) = packet(encoded.clone().into()).unwrap();
        assert!(rest.is_empty());
        assert_eq!(last, first.wrapping_add(1));
        assert_eq!(parsed.as_ref(), payload.as_ref());
        let mut reader = PacketReader::new(encoded.as_ref());
        assert_eq!(reader.next_async().await.unwrap().unwrap().0, last);
        assert!(reader.next_async().await.unwrap().is_none());

        let mut deferred = PacketReader::new(&b""[..]);
        deferred.prepend_packet(last, parsed.as_ref());
        assert_eq!(deferred.bytes.as_ref(), encoded.as_ref());
        let (deferred_last, deferred_payload) = deferred.next_async().await.unwrap().unwrap();
        assert_eq!(deferred_last, last);
        assert_eq!(deferred_payload.as_ref(), payload.as_ref());
    }
    for final_length in [0usize, 3] {
        let encoded = mock_packet(payload.slice(..U24_MAX + final_length), 255);
        let mut malformed = encoded.to_vec();
        malformed[U24_MAX + 7] = 7;
        assert!(matches!(
            packet(bytes::Bytes::from(malformed.clone()).into()),
            Err(nom::Err::Failure(_))
        ));
        let mut reader = PacketReader::new(malformed.as_slice());
        assert_eq!(
            reader
                .next_async()
                .await
                .err()
                .expect("bad continuation")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }
    // Reject the next full continuation too, not only the terminal fragment.
    let mut encoded = mock_packet(bytes::Bytes::from(vec![0; U24_MAX * 2]), 254).to_vec();
    encoded[U24_MAX + 7] = 1;
    assert!(matches!(
        packet(bytes::Bytes::from(encoded).into()),
        Err(nom::Err::Failure(_))
    ));
}

#[tokio::test]
async fn compressed_partial_headers_are_not_clean_eof_and_logical_limit_precedes_next_body() {
    for zstd in [false, true] {
        for length in 1..7 {
            let input = vec![0u8; length];
            let mut reader = PacketReader::new(input.as_slice());
            if zstd {
                reader.enable_zstd_compression();
            } else {
                reader.enable_compression();
            }
            let error = reader
                .next_async()
                .await
                .err()
                .expect("partial compression header");
            assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
            assert_eq!(
                error.to_string(),
                "truncated compressed MySQL packet header"
            );
        }
        let mut reader = PacketReader::new(&b""[..]);
        if zstd {
            reader.enable_zstd_compression();
        } else {
            reader.enable_compression();
        }
        assert!(reader.next_async().await.unwrap().is_none());

        // The first envelope contains only a logical header. No need to read
        // or allocate the body advertised above the configured logical cap.
        let input = [
            4, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 3, 0, 0, 1, 0, 0, 0, b'a', b'b', b'c',
        ];
        let mut reader = PacketReader::new(input.as_slice());
        reader.set_max_allowed_packet(4);
        if zstd {
            reader.enable_zstd_compression();
        } else {
            reader.enable_compression();
        }
        let error = reader
            .next_async()
            .await
            .err()
            .expect("logical payload bound");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "MySQL packet exceeds max_allowed_packet");
        assert_eq!(
            reader.compressed_sequence(),
            1,
            "second envelope was not consumed"
        );
    }
    let input = [5, 0, 0, 0, b'a', b'b', b'c', b'd', b'e'];
    let mut sync = PacketReader::new(input.as_slice());
    sync.set_max_allowed_packet(4);
    assert_eq!(
        sync.next().err().expect("sync payload bound").to_string(),
        "MySQL packet exceeds max_allowed_packet"
    );
    let mut asynchronous = PacketReader::new(input.as_slice());
    asynchronous.set_max_allowed_packet(4);
    assert_eq!(
        asynchronous
            .next_async()
            .await
            .err()
            .expect("async payload bound")
            .to_string(),
        "MySQL packet exceeds max_allowed_packet"
    );
}

#[test]
fn incomplete_continuation_does_not_publish_a_joined_packet_and_small_packet_borrows_owner() {
    let encoded = mock_packet(bytes::Bytes::from(vec![0; U24_MAX]), 255);
    for missing in 1..=4 {
        assert!(matches!(
            packet(encoded.slice(..encoded.len() - missing).into()),
            Err(nom::Err::Incomplete(_))
        ));
    }
    let encoded = bytes::Bytes::from_static(b"\x03\0\0\xffabc\x01\0\0\0z");
    let (rest, (sequence, parsed)) = packet(encoded.clone().into()).unwrap();
    assert_eq!(sequence, 255);
    assert_eq!(parsed.as_ref(), b"abc");
    assert_eq!(parsed.as_ptr(), encoded[4..].as_ptr());
    assert_eq!(rest.as_ref(), b"\x01\0\0\0z");
}

struct NetReadProbe {
    interrupts: usize,
    reads: std::sync::Arc<std::sync::Mutex<Vec<usize>>>,
}

impl tokio::io::AsyncRead for NetReadProbe {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.reads.lock().unwrap().push(buffer.remaining());
        if self.interrupts != 0 {
            self.interrupts -= 1;
            return std::task::Poll::Ready(Err(std::io::ErrorKind::Interrupted.into()));
        }
        buffer.put_slice(b"\x03\0\0\0abc");
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn actual_net_buffer_and_interrupted_retry_are_consumed_by_the_same_reader() {
    for size in [1024, 16384, 1048576] {
        let reads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut reader = PacketReader::new(NetReadProbe {
            interrupts: 1,
            reads: reads.clone(),
        });
        reader.set_network_settings(Some(std::sync::Arc::new(move || {
            Ok(crate::NetworkSettingsSnapshot {
                buffer_length: size,
                read_timeout: std::time::Duration::from_secs(1),
                write_timeout: std::time::Duration::from_secs(1),
                retry_count: 1,
            })
        })));
        let (sequence, packet) = reader.next_async().await.unwrap().unwrap();
        assert_eq!(sequence, 0);
        assert_eq!(packet.as_ref(), b"abc");
        assert_eq!(*reads.lock().unwrap(), vec![size, size]);
    }
    let reads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut reader = PacketReader::new(NetReadProbe {
        interrupts: 2,
        reads: reads.clone(),
    });
    reader.set_network_settings(Some(std::sync::Arc::new(|| {
        Ok(crate::NetworkSettingsSnapshot {
            buffer_length: 1024,
            read_timeout: std::time::Duration::from_secs(1),
            write_timeout: std::time::Duration::from_secs(1),
            retry_count: 1,
        })
    })));
    assert_eq!(
        reader
            .next_async()
            .await
            .err()
            .expect("retry cap must reject Interrupted")
            .kind(),
        std::io::ErrorKind::Interrupted
    );
    assert_eq!(*reads.lock().unwrap(), vec![1024, 1024]);
}

#[tokio::test]
async fn first_byte_idle_and_partial_packet_net_read_have_distinct_frontiers() {
    use tokio::io::AsyncWriteExt;
    let settings: crate::NetworkSettings = std::sync::Arc::new(|| {
        Ok(crate::NetworkSettingsSnapshot {
            buffer_length: 1024,
            read_timeout: std::time::Duration::from_millis(2),
            write_timeout: std::time::Duration::from_secs(1),
            retry_count: 1,
        })
    });
    let (mut peer, source) = tokio::io::duplex(1024);
    let mut reader = PacketReader::new(source);
    reader.set_network_settings(Some(settings.clone()));
    let error = reader
        .next_async_with_idle_timeout(Some(std::time::Duration::from_millis(2)))
        .await
        .err()
        .expect("idle reader must time out");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(error.to_string(), "MySQL connection idle timeout");
    peer.write_all(&[3, 0]).await.unwrap();
    let error = reader
        .next_async_with_idle_timeout(Some(std::time::Duration::from_secs(30)))
        .await
        .err()
        .expect("partial NET packet must time out");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(error.to_string(), "MySQL NET read timeout");
    let (mut peer, source) = tokio::io::duplex(1024);
    let mut reader = PacketReader::new(source);
    reader.enable_compression();
    reader.set_network_settings(Some(settings));
    peer.write_all(&[4, 0]).await.unwrap();
    assert_eq!(
        reader
            .next_async_with_idle_timeout(Some(std::time::Duration::from_secs(30)))
            .await
            .err()
            .expect("partial compressed NET packet must time out")
            .to_string(),
        "MySQL NET read timeout"
    );
}

fn mock_packet(mut data: bytes::Bytes, start_seq: u8) -> bytes::Bytes {
    let mut buf = BytesMut::new();
    let mut seq = start_seq;
    while data.len() >= U24_MAX {
        buf.extend_from_slice(&[0xff, 0xff, 0xff]);
        buf.put_u8(seq);
        buf.put(&data[0..U24_MAX]);
        data.advance(U24_MAX);
        seq = seq.wrapping_add(1);
    }
    let le_u64: [u8; 8] = data.len().to_le_bytes();
    let le_u24 = &le_u64[0..3];
    buf.extend_from_slice(le_u24);
    buf.put_u8(seq);
    buf.put(data);
    buf.freeze()
}

#[tokio::test]
async fn test_various_packet_size() {
    // test for off by one, and off by header size(3 bytes for length and 1 for seq num)
    let testcases = [
        0,
        1,
        2,
        PACKET_BUFFER_SIZE - 1 - 4,
        PACKET_BUFFER_SIZE - 1,
        PACKET_BUFFER_SIZE,
        PACKET_BUFFER_SIZE + 1,
        PACKET_BUFFER_SIZE + 1 + 4,
        PACKET_LARGE_BUFFER_SIZE - 4 - 1,
        PACKET_LARGE_BUFFER_SIZE - 4,
        PACKET_LARGE_BUFFER_SIZE - 1,
        PACKET_LARGE_BUFFER_SIZE,
        PACKET_LARGE_BUFFER_SIZE + 1,
        PACKET_LARGE_BUFFER_SIZE + 4,
        PACKET_LARGE_BUFFER_SIZE + 4 + 1,
        U24_MAX - 4 - 1,
        U24_MAX - 4,
        U24_MAX - 1,
        U24_MAX,
        U24_MAX + 1,
        U24_MAX + 4,
        U24_MAX + 4 + 1,
        U24_MAX * 2 - 4 - 1,
        U24_MAX * 2 - 4,
        U24_MAX * 2 - 1,
        U24_MAX * 2,
        U24_MAX * 2 + 1,
        U24_MAX * 2 + 4,
        U24_MAX * 2 + 4 + 1,
    ];
    for input_size in testcases {
        let large_data = bytes::Bytes::from(vec![0; input_size]);
        let packet = mock_packet(large_data, 0);
        let mut reader = PacketReader::new(packet.reader());
        let mut last_seq = 0;
        let mut total_size = 0;
        while let Some((seq, packet)) = reader.next().unwrap() {
            if seq != 0 {
                assert!(seq > last_seq);
            }
            total_size += packet.len();
            last_seq = seq;
        }
        assert_eq!(total_size, input_size);
    }
    for input_size in testcases {
        let large_data = bytes::Bytes::from(vec![0; input_size]);
        let packet = mock_packet(large_data, 0);
        let mut reader = PacketReader::new(packet.as_ref());
        let mut last_seq = 0;
        let mut total_size = 0;
        while let Some((seq, packet)) = reader.next_async().await.unwrap() {
            if seq != 0 {
                assert!(seq > last_seq);
            }
            total_size += packet.len();
            last_seq = seq;
        }
        assert_eq!(total_size, input_size);
    }
}

#[tokio::test]
async fn compressed_frames_bound_output_and_reject_truncation() {
    use std::io::Write;
    for zstd in [false, true] {
        let plain = [1, 0, 0, 0, 14];
        let compress = |data: &[u8]| {
            if zstd {
                zstd::stream::encode_all(data, 1).unwrap()
            } else {
                let mut encoder =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
                encoder.write_all(data).unwrap();
                encoder.finish().unwrap()
            }
        };
        for (data, declared, truncate, valid) in [
            (plain.to_vec(), 5usize, false, true),
            (vec![0; 1024 * 1024], 5, false, false),
            (plain.to_vec(), 6, false, false),
            (plain.to_vec(), 5, true, false),
        ] {
            let payload = compress(&data);
            let mut frame = Vec::new();
            frame.extend_from_slice(&payload.len().to_le_bytes()[..3]);
            frame.push(0);
            frame.extend_from_slice(&declared.to_le_bytes()[..3]);
            frame.extend_from_slice(&payload);
            if truncate {
                frame.pop();
            }
            let mut reader = PacketReader::new(frame.as_slice());
            if zstd {
                reader.enable_zstd_compression();
            } else {
                reader.enable_compression();
            }
            let result = reader.next_async().await;
            if valid {
                assert_eq!(&*result.unwrap().unwrap().1, &[14]);
                assert_eq!(reader.compressed_sequence(), 1);
            } else {
                assert!(
                    result.is_err(),
                    "zstd={zstd} declared={declared} truncate={truncate}"
                );
            }
        }
    }
}

#[tokio::test]
async fn compressed_frames_reject_an_out_of_order_outer_sequence() {
    let plain = [1, 0, 0, 0, 14];
    let payload = zstd::stream::encode_all(plain.as_slice(), 1).unwrap();
    let mut frame = Vec::new();
    frame.extend_from_slice(&payload.len().to_le_bytes()[..3]);
    frame.push(1);
    frame.extend_from_slice(&plain.len().to_le_bytes()[..3]);
    frame.extend_from_slice(&payload);
    let mut reader = PacketReader::new(frame.as_slice());
    reader.enable_zstd_compression();
    let error = match reader.next_async().await {
        Err(error) => error,
        Ok(_) => panic!("out-of-order compressed frame was accepted"),
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("received 1, expected 0"));
}

#[tokio::test]
async fn configured_packet_limit_applies_to_plain_and_compressed_payloads() {
    assert!(encoded_packet_exceeds_limit(&[5, 0, 0, 0], 4));
    assert!(!encoded_packet_exceeds_limit(&[4, 0, 0, 0], 4));

    let plain = mock_packet(bytes::Bytes::from_static(b"12345"), 0);
    let mut reader = PacketReader::new(plain.as_ref());
    reader.set_max_allowed_packet(4);
    assert!(reader.next_async().await.is_err());

    use std::io::Write;
    let encoded = [5, 0, 0, 0, b'1', b'2', b'3', b'4', b'5'];
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&encoded).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut frame = Vec::new();
    frame.extend_from_slice(&compressed.len().to_le_bytes()[..3]);
    frame.push(0);
    frame.extend_from_slice(&encoded.len().to_le_bytes()[..3]);
    frame.extend_from_slice(&compressed);
    let mut reader = PacketReader::new(frame.as_slice());
    reader.set_max_allowed_packet(4);
    reader.enable_compression();
    assert!(reader.next_async().await.is_err());
}
