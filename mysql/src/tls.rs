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

use std::io::IoSlice;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};
use tokio_rustls::server::TlsStream;
use tokio_rustls::{rustls::ServerConfig, TlsAcceptor};

use crate::commands::ClientHandshake;
use crate::myc::constants::CapabilityFlags;
use crate::packet_reader::PacketReader;
use crate::packet_writer::PacketWriter;
use crate::{AsyncMysqlIntermediary, AsyncMysqlShim, IntermediaryOptions};

pub async fn plain_run_with_options<B, R, W>(
    shim: B,
    writer: W,
    opts: IntermediaryOptions,
    init_params: (ClientHandshake, u8, CapabilityFlags, bool, PacketReader<R>),
) -> Result<(), B::Error>
where
    B: AsyncMysqlShim<W> + Send + Sync,
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    let (handshake, seq, client_capabilities, uncompressed_allowed, reader) = init_params;
    let reader = PacketReader::new(reader);
    let writer = PacketWriter::new(writer);

    let process_use_statement_on_query = opts.process_use_statement_on_query;
    let reject_connection_on_dbname_absence = opts.reject_connection_on_dbname_absence;
    let mut mi = AsyncMysqlIntermediary {
        client_capabilities,
        process_use_statement_on_query,
        reject_connection_on_dbname_absence,
        shim,
        reader,
        writer,
        zstd_compression_level: 3,
        secure_transport: false,
        uncompressed_allowed,
    };
    if let Err(error) = mi.init_after_ssl(handshake, seq).await {
        let _ = mi.shim.on_disconnect().await;
        return Err(error);
    }
    if mi
        .client_capabilities
        .contains(CapabilityFlags::CLIENT_COMPRESS)
    {
        mi.reader.enable_compression();
        mi.writer.enable_compression();
    } else if mi
        .client_capabilities
        .contains(CapabilityFlags::CLIENT_ZSTD_COMPRESSION_ALGORITHM)
    {
        mi.reader.enable_zstd_compression();
        mi.writer.enable_zstd_compression(mi.zstd_compression_level);
    }
    mi.run().await
}

pub async fn secure_run_with_options<B, R, W>(
    mut shim: B,
    writer: W,
    opts: IntermediaryOptions,
    tls_config: Arc<ServerConfig>,
    init_params: (ClientHandshake, u8, CapabilityFlags, bool, PacketReader<R>),
) -> Result<(), B::Error>
where
    B: AsyncMysqlShim<WriteHalf<TlsStream<Duplex<PacketReader<R>, W>>>> + Send + Sync,
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    let (handshake, seq, client_capabilities, uncompressed_allowed, reader) = init_params;
    let (reader, writer, session, peer_certificates) =
        switch_to_tls_session(tls_config, reader, writer).await?;
    shim.on_tls_session(session, &peer_certificates)?;
    let reader = PacketReader::new(reader);
    let writer = PacketWriter::new(writer);

    let process_use_statement_on_query = opts.process_use_statement_on_query;
    let reject_connection_on_dbname_absence = opts.reject_connection_on_dbname_absence;
    let mut mi = AsyncMysqlIntermediary {
        client_capabilities,
        process_use_statement_on_query,
        reject_connection_on_dbname_absence,
        shim,
        reader,
        writer,
        zstd_compression_level: 3,
        secure_transport: true,
        uncompressed_allowed,
    };
    if let Err(error) = mi.init_after_ssl(handshake, seq).await {
        let _ = mi.shim.on_disconnect().await;
        return Err(error);
    }
    if mi
        .client_capabilities
        .contains(CapabilityFlags::CLIENT_COMPRESS)
    {
        mi.reader.enable_compression();
        mi.writer.enable_compression();
    } else if mi
        .client_capabilities
        .contains(CapabilityFlags::CLIENT_ZSTD_COMPRESSION_ALGORITHM)
    {
        mi.reader.enable_zstd_compression();
        mi.writer.enable_zstd_compression(mi.zstd_compression_level);
    }
    mi.run().await
}

async fn switch_to_tls_session<R: AsyncRead + Send + Unpin, W: AsyncWrite + Send + Unpin>(
    config: Arc<ServerConfig>,
    reader: R,
    writer: W,
) -> std::io::Result<(
    ReadHalf<TlsStream<Duplex<R, W>>>,
    WriteHalf<TlsStream<Duplex<R, W>>>,
    crate::TlsSessionInfo,
    Vec<Vec<u8>>,
)> {
    let stream = Duplex::new(reader, writer);
    let acceptor = TlsAcceptor::from(config);
    let stream = acceptor.accept(stream).await?;
    let (_, connection) = stream.get_ref();
    let session = tls_session_info(connection)?;
    let peer_certificates = connection
        .peer_certificates()
        .unwrap_or_default()
        .iter()
        .map(|certificate| certificate.as_ref().to_vec())
        .collect();
    let (r, w) = tokio::io::split(stream);
    Ok((r, w, session, peer_certificates))
}

/// Borrow the native name of an actually negotiated suite. Unknown suites
/// must be reviewed before publication; Debug text is not a protocol fact.
pub fn mysql_cipher_name(suite: tokio_rustls::rustls::CipherSuite) -> io::Result<&'static str> {
    use tokio_rustls::rustls::CipherSuite as C;
    Ok(match suite {
        C::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => "ECDHE-ECDSA-AES256-GCM-SHA384",
        C::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => "ECDHE-RSA-AES256-GCM-SHA384",
        C::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => "ECDHE-ECDSA-AES128-GCM-SHA256",
        C::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => "ECDHE-RSA-AES128-GCM-SHA256",
        C::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => "ECDHE-ECDSA-CHACHA20-POLY1305",
        C::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => "ECDHE-RSA-CHACHA20-POLY1305",
        C::TLS13_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
        C::TLS13_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
        C::TLS13_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
        _ => {
            return Err(io::Error::other(
                "negotiated TLS cipher has no native MySQL name",
            ));
        }
    })
}

/// Capture every required negotiated fact before splitting the actual
/// stream. An unfinished/unknown handshake cannot publish a plaintext tuple.
pub fn tls_session_info(
    connection: &tokio_rustls::rustls::ServerConnection,
) -> io::Result<crate::TlsSessionInfo> {
    use tokio_rustls::rustls::{HandshakeKind, ProtocolVersion};
    if connection.is_handshaking() {
        return Err(io::Error::other("TLS handshake has not completed"));
    }
    let suite = connection
        .negotiated_cipher_suite()
        .ok_or_else(|| io::Error::other("completed TLS handshake has no negotiated cipher"))?;
    let version = match connection.protocol_version() {
        Some(ProtocolVersion::TLSv1_2) => "TLSv1.2",
        Some(ProtocolVersion::TLSv1_3) => "TLSv1.3",
        _ => {
            return Err(io::Error::other(
                "completed TLS handshake has no supported version",
            ));
        }
    };
    let reused = match connection.handshake_kind() {
        Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest) => false,
        Some(HandshakeKind::Resumed) => true,
        _ => {
            return Err(io::Error::other(
                "completed TLS handshake has no handshake kind",
            ));
        }
    };
    Ok(crate::TlsSessionInfo {
        cipher: mysql_cipher_name(suite.suite())?,
        version,
        reused,
    })
}

pin_project! {
    #[derive(Clone, Debug)]
    pub struct Duplex<R, W> {
        #[pin]
        reader: R,
        #[pin]
        writer: W,
    }
}

impl<R, W> Duplex<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

impl<R: AsyncRead, W> AsyncRead for Duplex<R, W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self.project().reader, cx, buf)
    }
}

impl<R, W: AsyncWrite> AsyncWrite for Duplex<R, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self.project().writer, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(self.project().writer, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_shutdown(self.project().writer, cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        AsyncWrite::poll_write_vectored(self.project().writer, cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        AsyncWrite::is_write_vectored(&self.writer)
    }
}
