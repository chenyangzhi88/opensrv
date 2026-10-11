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

use std::io;
use std::io::prelude::*;

use std::iter::Enumerate;
use std::ops::RangeFrom;

use bytes::BytesMut;
use flate2::read::ZlibDecoder;
use nom::Needed;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;

#[cfg(test)]
#[path = "tests/packet_reader.rs"]
pub(crate) mod tests;

pub(crate) const PACKET_BUFFER_SIZE: usize = 4_096;
pub(crate) const PACKET_LARGE_BUFFER_SIZE: usize = 1_048_576;
pub(crate) const DEFAULT_MAX_ALLOWED_PACKET: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum CompressionAlgorithm {
    #[default]
    None,
    Zlib,
    Zstd,
}

fn calc_new_buf_size_with_minimum(last_buf_size: usize, minimum: usize) -> usize {
    if last_buf_size >= minimum * 2 {
        // if packet is already too large, use larger buffer to avoid multiple allocation
        PACKET_LARGE_BUFFER_SIZE
    } else {
        std::cmp::max(minimum, last_buf_size * 2)
    }
}

/// reuse old buffer if possible, otherwise create a new buffer
///
/// return (the idx to start writing to the buffer,  and the buffer itself)
///
/// will copy the remain bytes from the old buffer to the new buffer if reusing
fn reuse_or_create_buf(old_buf: bytes::Bytes, last_buf_size: usize) -> (usize, BytesMut) {
    reuse_or_create_buf_with_minimum(old_buf, last_buf_size, PACKET_BUFFER_SIZE)
}

fn reuse_or_create_buf_with_minimum(
    old_buf: bytes::Bytes,
    last_buf_size: usize,
    minimum: usize,
) -> (usize, BytesMut) {
    let new_buf_size = calc_new_buf_size_with_minimum(last_buf_size, minimum);
    match old_buf.try_into_mut() {
        Ok(mut unique) => {
            let len = unique.len();
            let resize_buf = if new_buf_size <= len {
                // if new buffer is smaller than old buffer, just double the size
                len * 2
            } else {
                new_buf_size
            };
            debug_assert!(len < resize_buf);
            // resize will save old bytes unchanged and fill the rest with 0
            unique.resize(resize_buf, 0);
            (len, unique)
        }
        Err(remain) => {
            let mut buf = BytesMut::with_capacity(new_buf_size);
            buf.resize(new_buf_size, 0);
            // if old buffer still contain bytes unread, need to save those bytes too
            buf[0..remain.len()].copy_from_slice(&remain);
            (remain.len(), buf)
        }
    }
}

// A pending read may be dropped by the response/peer select. The bytes already
// read still belong to this reader, not to that cancellable future. Restore the
// same allocation on both completion and cancellation without copying prefix.
struct ReadBufferGuard<'a> {
    owner: &'a mut bytes::Bytes,
    buffer: BytesMut,
    initialized: usize,
}

impl<'a> ReadBufferGuard<'a> {
    fn new(owner: &'a mut bytes::Bytes, last_size: usize, minimum: usize) -> Self {
        let (initialized, buffer) =
            reuse_or_create_buf_with_minimum(std::mem::take(owner), last_size, minimum);
        Self {
            owner,
            buffer,
            initialized,
        }
    }

    fn remaining(&mut self) -> &mut [u8] {
        &mut self.buffer[self.initialized..]
    }

    fn complete(&mut self, count: usize) {
        self.initialized += count;
    }
}

impl Drop for ReadBufferGuard<'_> {
    fn drop(&mut self) {
        self.buffer.truncate(self.initialized);
        *self.owner = std::mem::take(&mut self.buffer).freeze();
    }
}

pub struct PacketReader<R> {
    bytes: bytes::Bytes,
    pub r: R,
    compression: CompressionAlgorithm,
    compressed_bytes: bytes::Bytes,
    compressed_seq: u8,
    new_command_in_progress: bool,
    max_allowed_packet: usize,
    network_settings: Option<crate::NetworkSettings>,
}

impl<R> PacketReader<R> {
    pub fn new(r: R) -> Self {
        PacketReader {
            bytes: bytes::Bytes::new(),
            r,
            compression: CompressionAlgorithm::None,
            compressed_bytes: bytes::Bytes::new(),
            compressed_seq: 0,
            new_command_in_progress: false,
            max_allowed_packet: DEFAULT_MAX_ALLOWED_PACKET,
            network_settings: None,
        }
    }

    pub(crate) fn set_max_allowed_packet(&mut self, max_allowed_packet: usize) {
        self.max_allowed_packet = max_allowed_packet;
    }

    pub(crate) fn set_network_settings(&mut self, settings: Option<crate::NetworkSettings>) {
        self.network_settings = settings;
    }

    fn network_buffer_length(&self) -> io::Result<usize> {
        self.network_settings
            .as_ref()
            .map_or(Ok(PACKET_BUFFER_SIZE), |read| {
                read().map(|value| value.buffer_length)
            })
    }

    pub fn enable_compression(&mut self) {
        self.enable_compression_algorithm(CompressionAlgorithm::Zlib);
    }

    pub fn enable_zstd_compression(&mut self) {
        self.enable_compression_algorithm(CompressionAlgorithm::Zstd);
    }

    fn enable_compression_algorithm(&mut self, compression: CompressionAlgorithm) {
        self.compression = compression;
        self.bytes = bytes::Bytes::new();
        self.compressed_bytes = bytes::Bytes::new();
        self.compressed_seq = 0;
        self.new_command_in_progress = false;
    }

    pub(crate) fn reset_compressed_sequence(&mut self) {
        if self.compression != CompressionAlgorithm::None {
            self.compressed_seq = 0;
        }
    }

    pub(crate) fn compressed_sequence(&self) -> u8 {
        self.compressed_seq
    }

    pub(crate) fn set_compressed_sequence(&mut self, sequence: u8) {
        if self.compression != CompressionAlgorithm::None {
            self.compressed_seq = sequence;
        }
    }

    /// Push an already decoded command back in front of unread bytes. This is used when a
    /// pipelining client sends its next command immediately after receiving the final response
    /// packet while the query future is completing bookkeeping.
    pub(crate) fn prepend_packet(&mut self, last_seq: u8, payload: &[u8]) {
        let mut encoded = BytesMut::with_capacity(
            payload
                .len()
                .saturating_add(8)
                .saturating_add(self.bytes.len()),
        );
        let mut offset = 0usize;
        // packet() returns the final physical sequence, which the response
        // writer needs. Reconstruct this same packet's first sequence rather
        // than assigning that final sequence to every deferred continuation.
        let mut seq = first_sequence(last_seq, payload.len());
        loop {
            let remaining = payload.len().saturating_sub(offset);
            let chunk_len = remaining.min(crate::U24_MAX);
            encoded.extend_from_slice(&[
                (chunk_len & 0xff) as u8,
                ((chunk_len >> 8) & 0xff) as u8,
                ((chunk_len >> 16) & 0xff) as u8,
                seq,
            ]);
            encoded.extend_from_slice(&payload[offset..offset + chunk_len]);
            offset += chunk_len;
            seq = seq.wrapping_add(1);
            if chunk_len < crate::U24_MAX {
                break;
            }
            if offset == payload.len() {
                encoded.extend_from_slice(&[0, 0, 0, seq]);
                break;
            }
        }
        encoded.extend_from_slice(&self.bytes);
        self.bytes = encoded.freeze();
    }
}

impl<R: Read> PacketReader<R> {
    #[allow(dead_code)]
    pub fn next(&mut self) -> io::Result<Option<(u8, Packet)>> {
        loop {
            let last_buffer_size = self.bytes.len();
            // Check the declared logical length before the continuation parser
            // allocates its joined payload, even when all bytes are buffered.
            if encoded_packet_exceeds_limit(&self.bytes, self.max_allowed_packet) {
                return Err(packet_too_large());
            }
            if !self.bytes.is_empty() {
                // coping `bytes::Bytes` are very cheap, just move the pointer and increase the ref count.
                match packet(self.bytes.clone().into()) {
                    Ok((rest, p)) => {
                        if p.1.len() > self.max_allowed_packet {
                            return Err(packet_too_large());
                        }
                        // most time the `rest` is either empty or very small, so it's cheap to copy it later into next buffer
                        self.bytes = rest.into();
                        return Ok(Some(p));
                    }
                    Err(nom::Err::Incomplete(_)) | Err(nom::Err::Error(_)) => {}
                    Err(nom::Err::Failure(_)) => {
                        let err = Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "malformed MySQL packet framing",
                        ));
                        return err;
                    }
                }
            }

            // read more buffer
            let (start, mut buf) =
                reuse_or_create_buf(std::mem::take(&mut self.bytes), last_buffer_size);
            let read_cnt = self.r.read(&mut buf[start..])?;
            buf.truncate(start + read_cnt);
            self.bytes = buf.freeze();

            // for a [TcpStream], returning zero indicates the connection was shut down correctly.
            if read_cnt == 0 {
                if self.bytes.is_empty() {
                    return Ok(None);
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("{} unhandled bytes", self.bytes.len()),
                    ));
                }
            }
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PacketReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // if our buffer have content, send those immediately
        if !self.bytes.is_empty() {
            buf.put_slice(&self.bytes);
            self.bytes.clear();
            std::task::Poll::Ready(Ok(()))
        } else {
            std::pin::Pin::new(&mut self.r).poll_read(cx, buf)
        }
    }
}

impl<R: AsyncRead + Unpin> PacketReader<R> {
    async fn read_network(
        reader: &mut R,
        network_settings: Option<&crate::NetworkSettings>,
        buffer: &mut [u8],
        partial: bool,
        idle: Option<std::time::Duration>,
    ) -> io::Result<usize> {
        let mut retries = 0;
        loop {
            let settings = network_settings.map(|read| read()).transpose()?;
            let timeout = if partial {
                settings.map(|value| value.read_timeout)
            } else {
                idle
            };
            let read = reader.read(buffer);
            let result = match timeout {
                Some(timeout) => tokio::time::timeout(timeout, read).await.map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        if partial {
                            "MySQL NET read timeout"
                        } else {
                            "MySQL connection idle timeout"
                        },
                    )
                })?,
                None => read.await,
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

    async fn read_compressed_frame(
        &mut self,
        idle: Option<std::time::Duration>,
    ) -> io::Result<bool> {
        while self.compressed_bytes.len() < 7 {
            let mut buffer = vec![0u8; self.network_buffer_length()?];
            let partial = !self.compressed_bytes.is_empty() || !self.bytes.is_empty();
            let read = Self::read_network(
                &mut self.r,
                self.network_settings.as_ref(),
                &mut buffer,
                partial,
                idle,
            )
            .await?;
            if read == 0 {
                return if self.compressed_bytes.is_empty() {
                    Ok(false)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated compressed MySQL packet header",
                    ))
                };
            }
            buffer.truncate(read);
            let mut combined = BytesMut::with_capacity(self.compressed_bytes.len() + read);
            combined.extend_from_slice(&self.compressed_bytes);
            combined.extend_from_slice(&buffer);
            self.compressed_bytes = combined.freeze();
        }
        let compressed_len = (self.compressed_bytes[0] as usize)
            | ((self.compressed_bytes[1] as usize) << 8)
            | ((self.compressed_bytes[2] as usize) << 16);
        let uncompressed_len = (self.compressed_bytes[4] as usize)
            | ((self.compressed_bytes[5] as usize) << 8)
            | ((self.compressed_bytes[6] as usize) << 16);
        let sequence = self.compressed_bytes[3];
        if sequence != self.compressed_seq {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "compressed MySQL packet out of order: received {sequence}, expected {}",
                    self.compressed_seq
                ),
            ));
        }
        if compressed_len > self.max_allowed_packet || uncompressed_len > self.max_allowed_packet {
            return Err(compressed_packet_too_large());
        }
        while self.compressed_bytes.len() < 7 + compressed_len {
            let mut buffer = vec![
                0u8;
                (7 + compressed_len - self.compressed_bytes.len())
                    .max(self.network_buffer_length()?)
            ];
            let read = Self::read_network(
                &mut self.r,
                self.network_settings.as_ref(),
                &mut buffer,
                true,
                None,
            )
            .await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated compressed MySQL packet",
                ));
            }
            buffer.truncate(read);
            let mut combined = BytesMut::with_capacity(self.compressed_bytes.len() + read);
            combined.extend_from_slice(&self.compressed_bytes);
            combined.extend_from_slice(&buffer);
            self.compressed_bytes = combined.freeze();
        }
        let payload = self.compressed_bytes.slice(7..7 + compressed_len);
        self.compressed_bytes = self.compressed_bytes.slice(7 + compressed_len..);
        let decoded = if uncompressed_len == 0 {
            payload.to_vec()
        } else {
            let mut decoded = Vec::with_capacity(uncompressed_len);
            match self.compression {
                CompressionAlgorithm::Zlib => {
                    ZlibDecoder::new(payload.as_ref())
                        .take(uncompressed_len as u64 + 1)
                        .read_to_end(&mut decoded)?;
                }
                CompressionAlgorithm::Zstd => {
                    zstd::stream::Decoder::new(payload.as_ref())?
                        .take(uncompressed_len as u64 + 1)
                        .read_to_end(&mut decoded)?;
                }
                CompressionAlgorithm::None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "received a compressed frame without negotiated compression",
                    ));
                }
            }
            if decoded.len() != uncompressed_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "compressed MySQL packet length mismatch",
                ));
            }
            decoded
        };
        let mut combined = BytesMut::with_capacity(self.bytes.len() + decoded.len());
        combined.extend_from_slice(&self.bytes);
        combined.extend_from_slice(&decoded);
        self.bytes = combined.freeze();
        // No await remains between decoding and publishing these bytes. A
        // cancelled body read must retry this same header under the same seq.
        self.compressed_seq = self.compressed_seq.wrapping_add(1);
        Ok(true)
    }

    pub async fn next_async(&mut self) -> io::Result<Option<(u8, Packet)>> {
        self.next_async_with_idle_timeout(None).await
    }

    // A new command resets both native NET counters. Authentication and
    // LOCAL transfers instead consume the current exchange's writer counter.
    pub(crate) async fn next_async_new_command(
        &mut self,
        idle: Option<std::time::Duration>,
    ) -> io::Result<Option<(u8, Packet)>> {
        if !self.new_command_in_progress {
            self.reset_compressed_sequence();
            self.new_command_in_progress = true;
        }
        let packet = self.next_async_with_idle_timeout(idle).await;
        self.new_command_in_progress = false;
        let packet = packet?;
        check_sequence(packet, 0)
    }

    pub(crate) async fn next_async_in_exchange(
        &mut self,
        expected: u8,
    ) -> io::Result<Option<(u8, Packet)>> {
        // LOCAL admission can win over a pending next-command peek, then
        // publish its filename request. This explicit same-exchange frontier
        // supersedes the peek, without discarding its bytes or resetting NET.
        self.new_command_in_progress = false;
        let packet = self.next_async().await?;
        check_sequence(packet, expected)
    }

    pub(crate) async fn next_async_with_idle_timeout(
        &mut self,
        idle: Option<std::time::Duration>,
    ) -> io::Result<Option<(u8, Packet)>> {
        loop {
            let last_buffer_size = self.bytes.len();
            // The compression envelope is a transport chunk, not the logical
            // packet bound. Its decoded stream uses the same length gate.
            if encoded_packet_exceeds_limit(&self.bytes, self.max_allowed_packet) {
                return Err(packet_too_large());
            }
            if !self.bytes.is_empty() {
                match packet(self.bytes.clone().into()) {
                    Ok((rest, p)) => {
                        if p.1.len() > self.max_allowed_packet {
                            return Err(packet_too_large());
                        }
                        self.bytes = rest.into();
                        return Ok(Some(p));
                    }
                    Err(nom::Err::Incomplete(_)) | Err(nom::Err::Error(_)) => {}
                    Err(nom::Err::Failure(_)) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "malformed MySQL packet framing",
                        ));
                    }
                }
            }

            if self.compression != CompressionAlgorithm::None {
                if !self.read_compressed_frame(idle).await? {
                    if self.bytes.is_empty() {
                        return Ok(None);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("{} unhandled compressed bytes", self.bytes.len()),
                    ));
                }
                continue;
            }
            // read more buffer
            let minimum = self.network_buffer_length()?;
            let partial = !self.bytes.is_empty();
            let mut buffer = ReadBufferGuard::new(&mut self.bytes, last_buffer_size, minimum);
            let read_cnt = Self::read_network(
                &mut self.r,
                self.network_settings.as_ref(),
                buffer.remaining(),
                partial,
                idle,
            )
            .await?;
            buffer.complete(read_cnt);
            drop(buffer);

            if read_cnt == 0 {
                if self.bytes.is_empty() {
                    return Ok(None);
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("{} unhandled bytes", self.bytes.len()),
                    ));
                }
            }
        }
    }
}

fn first_sequence(last: u8, length: usize) -> u8 {
    last.wrapping_sub((length / U24_MAX) as u8)
}

fn check_sequence(packet: Option<(u8, Packet)>, expected: u8) -> io::Result<Option<(u8, Packet)>> {
    if let Some((last, payload)) = &packet {
        let received = first_sequence(*last, payload.len());
        if received != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("MySQL packet out of order: received {received}, expected {expected}"),
            ));
        }
    }
    Ok(packet)
}

pub(crate) fn encoded_packet_exceeds_limit(input: &[u8], max_allowed_packet: usize) -> bool {
    let mut offset = 0usize;
    let mut payload_len = 0usize;
    loop {
        let Some(header) = input.get(offset..offset.saturating_add(4)) else {
            return false;
        };
        let chunk_len =
            usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
        payload_len = match payload_len.checked_add(chunk_len) {
            Some(payload_len) if payload_len <= max_allowed_packet => payload_len,
            _ => return true,
        };
        if chunk_len < crate::U24_MAX {
            return false;
        }
        let Some(next) = offset
            .checked_add(4)
            .and_then(|offset| offset.checked_add(chunk_len))
        else {
            return true;
        };
        if input.len() < next {
            return false;
        }
        offset = next;
    }
}

fn packet_too_large() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "MySQL packet exceeds max_allowed_packet",
    )
}

fn compressed_packet_too_large() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "compressed MySQL packet exceeds max_allowed_packet",
    )
}

/// Bytes wrapper for nom, allowing nom to parse bytes::Bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NomBytes(bytes::Bytes);

impl NomBytes {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<&[u8]> for NomBytes {
    fn from(value: &[u8]) -> Self {
        NomBytes(bytes::Bytes::copy_from_slice(value))
    }
}

impl From<bytes::Bytes> for NomBytes {
    fn from(value: bytes::Bytes) -> Self {
        NomBytes(value)
    }
}

impl From<NomBytes> for bytes::Bytes {
    fn from(value: NomBytes) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for NomBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl nom::InputTake for NomBytes {
    fn take(&self, count: usize) -> Self {
        NomBytes(self.0.slice(0..count))
    }

    fn take_split(&self, count: usize) -> (Self, Self) {
        let mut prefix = self.0.clone();
        let suffix = prefix.split_off(count);
        (NomBytes(suffix), NomBytes(prefix))
    }
}

impl nom::Compare<&[u8]> for NomBytes {
    fn compare(&self, t: &[u8]) -> nom::CompareResult {
        self.0.as_ref().compare(t)
    }

    fn compare_no_case(&self, t: &[u8]) -> nom::CompareResult {
        self.0.as_ref().compare_no_case(t)
    }
}

impl nom::InputLength for NomBytes {
    fn input_len(&self) -> usize {
        self.0.len()
    }
}

impl nom::InputIter for NomBytes {
    type Item = u8;
    type Iter = Enumerate<Self::IterElem>;
    type IterElem = bytes::buf::IntoIter<bytes::Bytes>;

    #[inline]
    fn iter_indices(&self) -> Self::Iter {
        self.iter_elements().enumerate()
    }
    #[inline]
    fn iter_elements(&self) -> Self::IterElem {
        self.0.clone().into_iter()
    }
    #[inline]
    fn position<P>(&self, predicate: P) -> Option<usize>
    where
        P: Fn(Self::Item) -> bool,
    {
        self.0.iter().position(|b| predicate(*b))
    }
    #[inline]
    fn slice_index(&self, count: usize) -> Result<usize, Needed> {
        if self.0.len() >= count {
            Ok(count)
        } else {
            Err(Needed::new(count - self.0.len()))
        }
    }
}

impl nom::Slice<RangeFrom<usize>> for NomBytes {
    fn slice(&self, range: RangeFrom<usize>) -> Self {
        NomBytes(self.0.slice(range))
    }
}

// A packet owns its `Bytes`; parsing a command must not keep the reader mutably borrowed.
#[derive(Clone)]
pub struct Packet {
    bytes: bytes::Bytes,
}

impl Packet {
    fn from_bytes(bytes: bytes::Bytes) -> Self {
        Packet { bytes }
    }

    /// A zero-copy owner of a checked command-body range. Keeping this Bytes
    /// alive protects the payload while the reader polls a successor packet.
    pub fn owned_range(&self, range: std::ops::Range<usize>) -> io::Result<bytes::Bytes> {
        if range.start > range.end || range.end > self.bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet range out of bounds",
            ));
        }
        Ok(self.bytes.slice(range))
    }
}

use crate::U24_MAX;
use std::ops::Deref;

impl Deref for Packet {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.bytes.as_ref()
    }
}

// A complete small packet borrows its existing Bytes owner. Continuations
// are validated in the same framing pass and joined only after the logical
// packet is complete, never repeatedly while waiting for its final fragment.
pub(crate) fn packet(i: NomBytes) -> nom::IResult<NomBytes, (u8, Packet)> {
    let bytes = i.as_ref();
    let malformed = || {
        nom::Err::Failure(nom::error::Error::new(
            i.clone(),
            nom::error::ErrorKind::Verify,
        ))
    };
    let mut offset = 0usize;
    let mut length = 0usize;
    let mut previous: Option<u8> = None;
    let final_sequence;
    loop {
        let available = bytes.len() - offset;
        if available < 4 {
            return Err(nom::Err::Incomplete(Needed::new(4 - available)));
        }
        let header = &bytes[offset..offset + 4];
        let chunk =
            usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
        let sequence = header[3];
        if previous.is_some_and(|previous| sequence != previous.wrapping_add(1)) {
            return Err(malformed());
        }
        if available - 4 < chunk {
            return Err(nom::Err::Incomplete(Needed::new(chunk - (available - 4))));
        }
        length = length.checked_add(chunk).ok_or_else(malformed)?;
        offset += 4 + chunk;
        if chunk < U24_MAX {
            final_sequence = sequence;
            break;
        }
        previous = Some(sequence);
    }
    let payload = if previous.is_none() {
        i.0.slice(4..offset)
    } else {
        let mut payload = BytesMut::with_capacity(length);
        let mut start = 0;
        while start < offset {
            let header = &bytes[start..start + 4];
            let chunk = usize::from(header[0])
                | (usize::from(header[1]) << 8)
                | (usize::from(header[2]) << 16);
            payload.extend_from_slice(&bytes[start + 4..start + 4 + chunk]);
            start += 4 + chunk;
        }
        payload.freeze()
    };
    Ok((
        NomBytes(i.0.slice(offset..)),
        (final_sequence, Packet::from_bytes(payload)),
    ))
}
