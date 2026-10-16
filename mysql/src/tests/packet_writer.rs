use crate::packet_writer::PacketWriter;
use crate::{NetworkSettings, NetworkSettingsSnapshot};
use std::io::{self, Write};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite};

#[tokio::test]
async fn emitted_packet_owner_exposes_next_sequence_after_actual_wrapping_continuations() {
    let payload = vec![7; crate::U24_MAX];
    let mut output = Vec::new();
    let mut writer = PacketWriter::new(&mut output);
    writer.set_seq(255);
    writer.write_all(&payload).unwrap();
    writer.end_packet().await.unwrap();
    writer.flush_all().await.unwrap();
    assert_eq!(writer.sequence(), 1); // full 255 plus mandatory empty 0
    drop(writer);
    let mut reader = crate::packet_reader::PacketReader::new(output.as_slice());
    let (last, actual) = reader.next_async_in_exchange(255).await.unwrap().unwrap();
    assert_eq!(last, 0);
    assert_eq!(actual.as_ref(), payload.as_slice());
    assert!(reader.next_async().await.unwrap().is_none());
    let mut output = Vec::new();
    let mut writer = PacketWriter::new(&mut output);
    writer.enable_compression();
    writer.set_compressed_sequence(255);
    writer.write_all(b"z").unwrap();
    writer.end_packet().await.unwrap();
    writer.flush_all().await.unwrap();
    assert_eq!(writer.compressed_sequence(), 0);
    drop(writer);
    assert_eq!(output[3], 255);
}

#[tokio::test]
async fn writer_reads_current_connection_settings_and_fails_closed_after_owner_close() {
    let closed = Arc::new(AtomicBool::new(false));
    let buffer = Arc::new(AtomicU64::new(1024));
    let settings: NetworkSettings = {
        let closed = closed.clone();
        let buffer = buffer.clone();
        Arc::new(move || {
            if closed.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "closed owner",
                ));
            }
            Ok(NetworkSettingsSnapshot {
                buffer_length: buffer.load(Ordering::Acquire) as usize,
                read_timeout: Duration::from_secs(1),
                write_timeout: Duration::from_secs(1),
                retry_count: 1,
            })
        })
    };
    let (sink, mut source) = tokio::io::duplex(8192);
    let mut writer = PacketWriter::new(sink);
    writer.set_network_settings(Some(settings));
    writer.write_all(b"first").unwrap();
    writer.end_packet().await.unwrap();
    let mut packet = [0; 9];
    source.read_exact(&mut packet).await.unwrap();
    assert_eq!(&packet, b"\x05\0\0\0first");
    buffer.store(4096, Ordering::Release);
    writer.write_all(b"second").unwrap();
    // Same SET response uses the now-current NET view, not a startup timeout copy.
    closed.store(true, Ordering::Release);
    assert_eq!(
        writer.end_packet().await.unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert_eq!(
        writer.write(b"later").unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert_eq!(
        writer.flush_all().await.unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
}

struct InterruptWriter {
    interrupts: usize,
    interrupt_after_bytes: usize,
    bytes: Arc<Mutex<Vec<u8>>>,
    pending: bool,
}
impl AsyncWrite for InterruptWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        if self.pending {
            return std::task::Poll::Pending;
        }
        let written = self.bytes.lock().unwrap().len();
        if self.interrupts != 0 && written >= self.interrupt_after_bytes {
            self.interrupts -= 1;
            return std::task::Poll::Ready(Err(io::ErrorKind::Interrupted.into()));
        }
        let size = bytes.len().min(2);
        self.bytes.lock().unwrap().extend_from_slice(&bytes[..size]);
        std::task::Poll::Ready(Ok(size))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if self.pending {
            return std::task::Poll::Pending;
        }
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
async fn actual_write_retries_only_interrupted_and_preserves_partial_packet_prefixes() {
    let settings: NetworkSettings = Arc::new(|| {
        Ok(NetworkSettingsSnapshot {
            buffer_length: 1024,
            read_timeout: Duration::from_millis(2),
            write_timeout: Duration::from_millis(2),
            retry_count: 1,
        })
    });
    for (interrupts, interrupt_after_bytes, expected) in [
        (1, 0, None),
        (2, 0, Some(io::ErrorKind::Interrupted)),
        // Inject after two actual header bytes, not only before the first write.
        (1, 2, None),
        // Inject after the header and two actual payload bytes as well.
        (1, 6, None),
    ] {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let mut writer = PacketWriter::new(InterruptWriter {
            interrupts,
            interrupt_after_bytes,
            bytes: bytes.clone(),
            pending: false,
        });
        writer.set_network_settings(Some(settings.clone()));
        writer.set_seq(7);
        writer.write_all(b"abc").unwrap();
        match expected {
            None => {
                writer.end_packet().await.unwrap();
                assert_eq!(
                    bytes.lock().unwrap().as_slice(),
                    b"\x03\0\0\x07abc",
                    "actual packet must contain its complete header, sequence and payload exactly once after {interrupts} interrupt(s) at prefix {interrupt_after_bytes}"
                );
            }
            Some(kind) => {
                assert_eq!(writer.end_packet().await.unwrap_err().kind(), kind);
                assert!(bytes.lock().unwrap().is_empty());
            }
        }
    }
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let mut writer = PacketWriter::new(InterruptWriter {
        interrupts: 0,
        interrupt_after_bytes: 0,
        bytes: bytes.clone(),
        pending: true,
    });
    writer.set_network_settings(Some(settings));
    writer.write_all(b"abc").unwrap();
    assert_eq!(
        writer.end_packet().await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        writer.flush_all().await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(bytes.lock().unwrap().is_empty());
}

struct PacketCapacityLease {
    ledger: Arc<Mutex<(usize, usize, usize, bool)>>,
    bytes: usize,
}

impl Drop for PacketCapacityLease {
    fn drop(&mut self) {
        let mut ledger = self.ledger.lock().unwrap();
        ledger.0 = ledger.0.checked_sub(self.bytes).unwrap();
    }
}

fn packet_capacity_admission(
    ledger: &Arc<Mutex<(usize, usize, usize, bool)>>,
) -> crate::CommandAllocationAdmission {
    let ledger = Arc::clone(ledger);
    Arc::new(move |bytes| {
        let mut state = ledger.lock().unwrap();
        if state.3
            || state
                .0
                .checked_add(bytes)
                .is_none_or(|total| total > state.1)
        {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "actual packet capacity refusal",
            ));
        }
        state.0 += bytes;
        state.2 = state.2.max(state.0);
        drop(state);
        Ok(Arc::new(PacketCapacityLease {
            ledger: Arc::clone(&ledger),
            bytes,
        }) as crate::CommandAllocation)
    })
}

#[test]
fn same_packet_buffer_keeps_capacity_permit_across_clear_and_failed_replacement() {
    let ledger = Arc::new(Mutex::new((0, 24, 0, false)));
    let mut buffer = crate::packet_writer::PacketBuilder::with_admission(Some(
        packet_capacity_admission(&ledger),
    ));
    buffer.write_all(b"original").unwrap();
    assert_eq!(ledger.lock().unwrap().0, 8);
    let original = buffer.as_slice().as_ptr();
    ledger.lock().unwrap().1 = 23; // old 8 plus selected replacement 16 minus one
    assert_eq!(
        buffer.write(b"!").unwrap_err().kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(buffer.as_slice(), b"original");
    assert_eq!(buffer.as_slice().as_ptr(), original);
    assert_eq!(
        ledger.lock().unwrap().0,
        8,
        "failure preserves the old grant"
    );
    ledger.lock().unwrap().1 = 24;
    buffer.write_all(b"!").unwrap();
    assert_eq!(buffer.as_slice(), b"original!");
    assert_eq!(ledger.lock().unwrap().0, 16);
    assert_eq!(
        ledger.lock().unwrap().2,
        24,
        "both allocations overlap before replacement"
    );
    buffer.clear();
    assert!(buffer.as_slice().is_empty());
    assert_eq!(
        ledger.lock().unwrap().0,
        16,
        "clear does not release live capacity"
    );
    ledger.lock().unwrap().3 = true;
    buffer.write_all(b"reuse").unwrap();
    assert_eq!(
        buffer.as_slice(),
        b"reuse",
        "no new allocation on capacity reuse"
    );
    assert_eq!(
        buffer.reserve(usize::MAX).unwrap_err().kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(buffer.as_slice(), b"reuse");
    drop(buffer);
    assert_eq!(ledger.lock().unwrap().0, 0);
}

#[tokio::test]
async fn real_packet_transport_failure_and_cancel_retire_all_inflight_buffer_permits() {
    for compression in [0, 1, 2] {
        let ledger = Arc::new(Mutex::new((0, 1 << 20, 0, false)));
        let state = Arc::new(Mutex::new(Vec::new()));
        let output = InterruptWriter {
            interrupts: 0,
            interrupt_after_bytes: usize::MAX,
            bytes: state,
            pending: true,
        };
        let mut writer = PacketWriter::new(output);
        writer.set_allocation_admission(Some(packet_capacity_admission(&ledger)));
        if compression == 1 {
            writer.enable_compression();
        }
        if compression == 2 {
            writer.enable_zstd_compression(3);
        }
        writer.write_all(&[0xff, 0, b'x']).unwrap();
        assert_eq!(ledger.lock().unwrap().0, 4);
        {
            let future = writer.end_packet();
            futures::pin_mut!(future);
            assert!(
                futures::poll!(future.as_mut()).is_pending(),
                "actual I/O is pending"
            );
            assert!(
                ledger.lock().unwrap().0 > 4,
                "framing and encoded buffers are also admitted"
            );
        }
        assert_eq!(
            ledger.lock().unwrap().0,
            0,
            "cancel retires the actual in-flight bytes"
        );
        writer.write_all(b"next").unwrap();
        assert_eq!(
            ledger.lock().unwrap().0,
            4,
            "same writer can own its next independent buffer"
        );
        drop(writer);
        assert_eq!(ledger.lock().unwrap().0, 0);
    }
    let ledger = Arc::new(Mutex::new((0, 64, 0, false)));
    let mut writer = PacketWriter::new(tokio::io::sink());
    writer.set_allocation_admission(Some(packet_capacity_admission(&ledger)));
    writer.write_all(b"raw").unwrap();
    ledger.lock().unwrap().3 = true;
    assert_eq!(
        writer.end_packet().await.unwrap_err().kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(
        ledger.lock().unwrap().0,
        0,
        "framing refusal drops bytes before their grants"
    );
}
