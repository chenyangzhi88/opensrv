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

use byteorder::{ByteOrder, LittleEndian};
use flate2::{write::ZlibEncoder, Compression};
use std::io;
use std::io::prelude::*;
use std::io::IoSlice;

use crate::packet_reader::CompressionAlgorithm;
use crate::U24_MAX;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// The writer of mysql packet.
/// - behaves as a sync writer, while build the packet
///   so that trivial async writes could be avoided
/// - behaves like a async writer, while writing data to the output stream
pub struct PacketWriter<W> {
    packet_builder: PacketBuilder,
    output_stream: W,
    compression: CompressionAlgorithm,
    zstd_level: i32,
    compressed_seq: u8,
    network_settings: Option<crate::NetworkSettings>,
}

// exports the internal builder as sync Write
impl<W> Write for PacketWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Packet construction consists of many small scalar writes. Reserve
        // its actual initial NET buffer once, not once per encoded field.
        // Transport write/flush still read current timeouts at each real I/O.
        if self.packet_builder.is_empty() {
            if let Some(read) = &self.network_settings {
                let minimum = read()?.buffer_length;
                if self.packet_builder.buffer.capacity() < minimum {
                    self.packet_builder
                        .reserve(minimum.saturating_sub(self.packet_builder.buffer.len()))?;
                }
            }
        }
        self.packet_builder.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.packet_builder.flush()
    }
}

impl<W> PacketWriter<W> {
    pub fn new(output_stream: W) -> Self {
        Self {
            packet_builder: PacketBuilder::new(),
            output_stream,
            compression: CompressionAlgorithm::None,
            zstd_level: 3,
            compressed_seq: 0,
            network_settings: None,
        }
    }
    pub(crate) fn set_network_settings(&mut self, settings: Option<crate::NetworkSettings>) {
        self.network_settings = settings;
    }
    pub(crate) fn set_allocation_admission(
        &mut self,
        admission: Option<crate::CommandAllocationAdmission>,
    ) {
        self.packet_builder.admission = admission;
    }

    pub(crate) fn allocation_admission(&self) -> Option<crate::CommandAllocationAdmission> {
        self.packet_builder.admission.clone()
    }

    pub fn set_seq(&mut self, seq: u8) {
        self.packet_builder.set_seq(seq);
    }

    pub(crate) fn sequence(&self) -> u8 {
        self.packet_builder.seq()
    }

    pub(crate) fn compressed_sequence(&self) -> u8 {
        self.compressed_seq
    }

    pub(crate) fn set_compressed_sequence(&mut self, seq: u8) {
        if self.compression != CompressionAlgorithm::None {
            self.compressed_seq = seq;
        }
    }

    pub fn enable_compression(&mut self) {
        self.compression = CompressionAlgorithm::Zlib;
        self.compressed_seq = 0;
    }

    pub fn enable_zstd_compression(&mut self, level: u8) {
        self.compression = CompressionAlgorithm::Zstd;
        self.zstd_level = i32::from(level);
        self.compressed_seq = 0;
    }
}

const PACKET_HEADER_SIZE: usize = 4;
impl<W: AsyncWrite + Unpin> PacketWriter<W> {
    async fn write_network(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        let mut retries = 0;
        while !bytes.is_empty() {
            let settings = self
                .network_settings
                .as_ref()
                .map(|read| read())
                .transpose()?;
            let slices = [IoSlice::new(bytes)];
            let write = self.output_stream.write_vectored(&slices);
            let result = match settings {
                Some(settings) => tokio::time::timeout(settings.write_timeout, write)
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "MySQL NET write timeout")
                    })?,
                None => write.await,
            };
            match result {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "MySQL NET write returned zero",
                    ));
                }
                Ok(written) => {
                    bytes = &bytes[written..];
                    retries = 0;
                }
                Err(error)
                    if error.kind() == io::ErrorKind::Interrupted
                        && retries < settings.map_or(0, |value| value.retry_count) =>
                {
                    retries += 1;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    /// Build packet(s) and write them to the output stream
    pub async fn end_packet(&mut self) -> io::Result<()> {
        let builder = &mut self.packet_builder;
        if !builder.is_empty() {
            let raw_packet = builder.take_buffer();

            if self.compression != CompressionAlgorithm::None {
                // Compression wraps the classic packet byte stream. Build the classic stream
                // first so payloads over 0xFFFFFF bytes retain their continuation headers (and
                // the required zero-length terminator at an exact boundary).
                let mut plain = PacketBuilder::with_admission(builder.admission.clone());
                append_classic_packets(&mut plain, raw_packet.as_slice(), builder)?;
                for chunk in plain.as_slice().chunks(U24_MAX) {
                    let compressed = match self.compression {
                        CompressionAlgorithm::Zlib => {
                            let mut encoder = ZlibEncoder::new(
                                PacketBuilder::with_admission(self.allocation_admission()),
                                Compression::default(),
                            );
                            encoder.write_all(chunk)?;
                            encoder.finish()?
                        }
                        CompressionAlgorithm::Zstd => {
                            let mut encoder = zstd::stream::write::Encoder::new(
                                PacketBuilder::with_admission(self.allocation_admission()),
                                self.zstd_level,
                            )?;
                            encoder.write_all(chunk)?;
                            encoder.finish()?
                        }
                        CompressionAlgorithm::None => unreachable!(),
                    };
                    let (payload, uncompressed_len) = if compressed.as_slice().len() < chunk.len() {
                        (compressed.as_slice(), chunk.len())
                    } else {
                        (chunk, 0)
                    };
                    let mut header = [0u8; 7];
                    LittleEndian::write_u24(&mut header[..3], payload.len() as u32);
                    header[3] = self.compressed_seq;
                    LittleEndian::write_u24(&mut header[4..], uncompressed_len as u32);
                    self.compressed_seq = self.compressed_seq.wrapping_add(1);
                    self.write_network(&header).await?;
                    self.write_network(payload).await?;
                }
                drop(plain);
                drop(raw_packet);
                return Ok(());
            }

            let mut plain = PacketBuilder::with_admission(builder.admission.clone());
            append_classic_packets(&mut plain, raw_packet.as_slice(), builder)?;
            self.write_network(plain.as_slice()).await?;
            drop(plain);
            drop(raw_packet);
            Ok(())
        } else {
            Ok(())
        }
    }

    pub async fn flush_all(&mut self) -> io::Result<()> {
        let mut retries = 0;
        loop {
            let settings = self
                .network_settings
                .as_ref()
                .map(|read| read())
                .transpose()?;
            let flush = self.output_stream.flush();
            let result = match settings {
                Some(settings) => tokio::time::timeout(settings.write_timeout, flush)
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "MySQL NET write timeout")
                    })?,
                None => flush.await,
            };
            match result {
                Err(error)
                    if error.kind() == io::ErrorKind::Interrupted
                        && retries < settings.map_or(0, |value| value.retry_count) =>
                {
                    retries += 1;
                }
                result => return result,
            }
        }
    }
}

fn append_classic_packets(
    output: &mut PacketBuilder,
    payload: &[u8],
    builder: &mut PacketBuilder,
) -> io::Result<()> {
    let headers = payload
        .len()
        .checked_div(U24_MAX)
        .and_then(|count| count.checked_add(1))
        .and_then(|count| count.checked_mul(PACKET_HEADER_SIZE))
        .and_then(|size| size.checked_add(payload.len()))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::OutOfMemory, "MySQL packet framing overflow")
        })?;
    output.reserve(headers)?;
    for chunk in payload.chunks(U24_MAX) {
        let mut header = [0; PACKET_HEADER_SIZE];
        LittleEndian::write_u24(&mut header, chunk.len() as u32);
        header[3] = builder.seq();
        output.write_all(&header)?;
        output.write_all(chunk)?;
        builder.increase_seq();
    }
    if payload.len() % U24_MAX == 0 {
        output.write_all(&[0, 0, 0, builder.seq()])?;
        builder.increase_seq();
    }
    Ok(())
}

// Builder that exports as sync `Write`, so that  trivial scattered async writes
// could be avoided during constructing the packet, especially the writes in mod [writers]
pub(crate) struct PacketBuilder {
    buffer: Vec<u8>,
    // Fields drop in declaration order: bytes retire before their grant.
    allocation: Option<crate::CommandAllocation>,
    admission: Option<crate::CommandAllocationAdmission>,
    seq: u8,
}

impl Write for PacketBuilder {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.reserve(buf.len())?;
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl PacketBuilder {
    pub fn new() -> Self {
        Self::with_admission(None)
    }

    pub(crate) fn with_admission(admission: Option<crate::CommandAllocationAdmission>) -> Self {
        Self {
            buffer: Vec::new(),
            allocation: None,
            admission,
            seq: 0,
        }
    }

    /// Choose a capacity, admit it, and only then allocate its replacement.
    /// Power-of-two capacities are an explicit amortized buffer policy, not a
    /// multiplier used to estimate encoded values or allocator-private buckets.
    /// The old bytes and their permit stay intact through every failure.
    pub(crate) fn reserve(&mut self, additional: usize) -> io::Result<()> {
        let required = self.buffer.len().checked_add(additional).ok_or_else(|| {
            io::Error::new(io::ErrorKind::OutOfMemory, "MySQL packet capacity overflow")
        })?;
        if required <= self.buffer.capacity() {
            return Ok(());
        }
        let capacity = required.checked_next_power_of_two().unwrap_or(required);
        let mut allocation = self
            .admission
            .as_ref()
            .map(|admit| admit(capacity))
            .transpose()?;
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(capacity)
            .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
        // std does not promise an allocator-exact capacity. Any reported extra
        // capacity is admitted before publishing or copying into this buffer.
        if replacement.capacity() != capacity {
            allocation = self
                .admission
                .as_ref()
                .map(|admit| admit(replacement.capacity()))
                .transpose()?;
        }
        replacement.extend_from_slice(&self.buffer);
        let previous_buffer = std::mem::replace(&mut self.buffer, replacement);
        let previous_allocation = std::mem::replace(&mut self.allocation, allocation);
        drop(previous_buffer);
        drop(previous_allocation);
        Ok(())
    }

    pub(crate) fn resize_zeroed(&mut self, length: usize) -> io::Result<()> {
        self.reserve(length.saturating_sub(self.buffer.len()))?;
        self.buffer.resize(length, 0);
        Ok(())
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.buffer
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    pub(crate) fn clear(&mut self) {
        // clear retains the physical allocation and therefore its same permit.
        self.buffer.clear();
    }

    fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    fn take_buffer(&mut self) -> Self {
        // Move the existing physical byte owner with its same grant. The
        // returned original builder drops bytes before its grant on every
        // success, I/O failure and cancelled future, not just the happy path.
        let mut packet = Self::with_admission(self.admission.clone());
        std::mem::swap(&mut packet.buffer, &mut self.buffer);
        std::mem::swap(&mut packet.allocation, &mut self.allocation);
        packet
    }

    fn set_seq(&mut self, seq: u8) {
        self.seq = seq;
    }

    fn increase_seq(&mut self) {
        self.seq = self.seq.wrapping_add(1);
    }

    fn seq(&self) -> u8 {
        self.seq
    }
}
