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

// Note to developers: you can find decent overviews of the protocol at
//
//   https://github.com/cwarden/mysql-proxy/blob/master/doc/protocol.rst
//
// and
//
//   https://mariadb.com/kb/en/library/clientserver-protocol/
//
// Wireshark also does a pretty good job at parsing the MySQL protocol.

extern crate mysql_common as myc;

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::io::Write;
use std::pin::Pin;

/// A read-only relation to the actual connection's validated NET variables.
/// Implementations must fail when the connection owner has gone away.
#[derive(Clone, Copy, Debug)]
pub struct NetworkSettingsSnapshot {
    pub buffer_length: usize,
    pub read_timeout: std::time::Duration,
    pub write_timeout: std::time::Duration,
    pub retry_count: u64,
}

pub type NetworkSettings =
    std::sync::Arc<dyn Fn() -> io::Result<NetworkSettingsSnapshot> + Send + Sync>;

/// Copied scalar facts borrowed from one actual server/current-command read.
/// This transport value grants no query, table, session or counter authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatisticsSnapshot {
    /// Native unsigned seconds: current command query start minus server boot.
    pub uptime: u64,
    /// Actual server THD count, rendered through the native signed int cast.
    pub threads: u32,
    /// The current command's global query ordinal, not session Questions.
    pub questions: u64,
    /// Actual global terminal long-query count.
    pub slow_queries: u64,
    /// Actual cumulative TABLE instance opens, including retired instances.
    pub opened_tables: u64,
    /// Actual server refresh version.
    pub flush_tables: u64,
    /// Actual current cached TABLE instances.
    pub open_tables: u32,
}

/// The original command packet owner for COM_STATISTICS's sole response.
pub struct StatisticsWriter<'a, W: AsyncWrite + Unpin> {
    writer: &'a mut PacketWriter<W>,
}

impl<W: AsyncWrite + Unpin> StatisticsWriter<'_, W> {
    /// Writes the native labels/spacing/integer QPS as one raw text packet.
    /// The complete seven-scalar rendering fits a 249-byte stack buffer.
    pub async fn write(self, facts: StatisticsSnapshot) -> io::Result<()> {
        let mut bytes = [0_u8; 249];
        let length = format_statistics(facts, &mut bytes)?;
        self.writer.write_all(&bytes[..length])?;
        self.writer.end_packet().await
    }

    /// Writes the backend's native condition as the sole ERR response.
    pub async fn error(self, kind: ErrorKind, message: &[u8]) -> io::Result<()> {
        writers::write_err(kind, message, self.writer).await
    }

    /// Preserves a backend condition's exact numeric identity and SQLSTATE.
    pub async fn error_raw(self, code: u16, state: &[u8; 5], message: &[u8]) -> io::Result<()> {
        writers::write_err_raw(code, state, message, self.writer).await
    }
}

fn format_statistics(facts: StatisticsSnapshot, bytes: &mut [u8; 249]) -> io::Result<usize> {
    struct Text<'a> {
        bytes: &'a mut [u8],
        length: usize,
    }
    impl std::fmt::Write for Text<'_> {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            let end = self
                .length
                .checked_add(value.len())
                .ok_or(std::fmt::Error)?;
            let target = self
                .bytes
                .get_mut(self.length..end)
                .ok_or(std::fmt::Error)?;
            target.copy_from_slice(value.as_bytes());
            self.length = end;
            Ok(())
        }
    }
    let mut text = Text { bytes, length: 0 };
    // sql_parse.cc uses unsigned longlong multiplication and casts the
    // quotient to uint; preserve those widths instead of an f64 approximation.
    let qps1000 = facts
        .questions
        .wrapping_mul(1000)
        .checked_div(facts.uptime)
        .unwrap_or(0);
    std::fmt::write(
        &mut text,
        format_args!(
            "Uptime: {}  Threads: {}  Questions: {}  Slow queries: {}  Opens: {}  Flush tables: {}  Open tables: {}  Queries per second avg: {}.{:03}",
            facts.uptime, facts.threads as i32, facts.questions,
            facts.slow_queries, facts.opened_tables, facts.flush_tables,
            facts.open_tables, (qps1000 / 1000) as u32, (qps1000 % 1000) as u32,
        ),
    )
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "statistics text exceeds native bound"))?;
    Ok(text.length)
}

/// Immutable facts from one completed server-side TLS handshake. These are
/// connection properties, not authentication authority or session counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsSessionInfo {
    pub cipher: &'static str,
    pub version: &'static str,
    pub reused: bool,
}

impl TlsSessionInfo {
    /// Native core callbacks for a THD with no bound SSL handle. Transport
    /// issuers never substitute this value for an unknown TLS negotiation.
    pub const NO_SSL: Self = Self {
        cipher: "",
        version: "",
        reused: false,
    };
}

use async_trait::async_trait;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
#[cfg(feature = "tls")]
use tokio_rustls::rustls::ServerConfig;

pub use crate::myc::constants::{CapabilityFlags, ColumnFlags, ColumnType, StatusFlags};
#[cfg(feature = "tls")]
pub use crate::tls::{
    mysql_cipher_name, plain_run_with_options, secure_run_with_options, tls_session_info,
};

mod commands;
mod errorcodes;
mod packet_reader;
mod packet_writer;
mod params;
mod resultset;
#[cfg(feature = "tls")]
mod tls;
mod value;
mod writers;

#[cfg(test)]
mod tests;

// max payload size 2^(24-1)
pub const U24_MAX: usize = 16_777_215;

/// Meta-information abot a single column, used either to describe a prepared statement parameter
/// or an output column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    /// This column's originating database/schema. Empty for expressions.
    pub database: Vec<u8>,
    /// This column's associated table.
    ///
    /// Note that this is *technically* the table's alias.
    pub table: Vec<u8>,
    /// This column's originating table. Empty for expressions.
    pub org_table: Vec<u8>,
    /// This column's name.
    ///
    /// Note that this is *technically* the column's alias.
    pub column: Vec<u8>,
    /// This column's originating column. Empty for expressions.
    pub org_column: Vec<u8>,
    /// Column length (in bytes) reported through COLUMN_DEFINITION41.
    /// Zero is a real length (for example NULL or an empty literal).
    pub collen: u32,
    /// Optional character set/collation id reported through COLUMN_DEFINITION41.
    /// None means "derive from type and flags".
    pub charset: Option<u16>,
    /// This column's type>
    pub coltype: ColumnType,
    /// Any flags associated with this column.
    ///
    /// Of particular interest are `ColumnFlags::UNSIGNED_FLAG` and `ColumnFlags::NOT_NULL_FLAG`.
    pub colflags: ColumnFlags,
    /// Optional decimals byte reported through COLUMN_DEFINITION41.
    /// None means "0".
    pub decimals: Option<u8>,
}

/// QueryStatusInfo represents the status of a query.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OkResponse {
    /// header
    pub header: u8,
    /// affected rows in update/insert
    pub affected_rows: u64,
    /// insert_id in update/insert
    pub last_insert_id: u64,
    /// StatusFlags associated with this query
    pub status_flags: StatusFlags,
    /// Warnings
    pub warnings: u16,
    /// Extra infomation
    pub info: String,
    /// session state change information
    pub session_state_info: Vec<u8>,
}

pub use crate::errorcodes::ErrorKind;
pub use crate::packet_reader::Packet;
pub use crate::params::{
    BindError, BindErrorPhase, BoundParameters, CommandAllocation, CommandAllocationAdmission,
    CommandAllocationLease, ParamParser, ParamValue, ParsedBindings, RawParamValue,
};
pub use crate::resultset::{InitWriter, QueryResultWriter, RowWriter, StatementMetaWriter};
pub use crate::value::{
    MySqlTextValue, ToMysqlValue, Value, ValueInner, decode::to_naive_datetime,
};
use crate::{commands::ClientHandshake, packet_reader::PacketReader, packet_writer::PacketWriter};

const SCRAMBLE_SIZE: usize = 20;
const MYSQL_NATIVE_PASSWORD: &str = "mysql_native_password";

/// The LOCAL preflight returns the same response writer, not a second response
/// or a transfer cache. `Completed` means the backend has consumed that writer
/// to publish its ordinary SQL error; no filename request may follow it.
pub enum LocalInfilePreflight<'writer, W> {
    Continue(QueryResultWriter<'writer, W>),
    Completed,
    Request {
        filename: Vec<u8>,
        results: QueryResultWriter<'writer, W>,
    },
}

enum CommandResponseOutcome<T, E> {
    Completed(Result<T, E>),
    Peer(io::Error),
}

fn query_attribute_capabilities(
    mut capabilities: CapabilityFlags,
    installed: bool,
) -> CapabilityFlags {
    capabilities.set(CapabilityFlags::CLIENT_QUERY_ATTRIBUTES, installed);
    capabilities
}

// The reader and writer remain the command loop's physical owners. This also
// protects the asynchronous LOCAL admission phase: EOF drops the borrowed SQL
// future before the backend cancellation callback and before any 0xfb packet.
async fn poll_command_response<R, F, T, E>(
    reader: &mut PacketReader<R>,
    response: F,
    peer_eof_message: &'static str,
) -> CommandResponseOutcome<T, E>
where
    R: AsyncRead + Unpin,
    F: Future<Output = Result<T, E>>,
{
    tokio::pin!(response);
    tokio::select! {
        biased;
        result = &mut response => CommandResponseOutcome::Completed(result),
        peer = reader.next_async_new_command(None) => match peer {
            Ok(Some((sequence, packet))) => {
                let packet = packet.to_vec();
                let result = response.await;
                reader.prepend_packet(sequence, &packet);
                CommandResponseOutcome::Completed(result)
            }
            Ok(None) => CommandResponseOutcome::Peer(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                peer_eof_message,
            )),
            Err(error) => CommandResponseOutcome::Peer(error),
        },
    }
}

#[async_trait]
/// Implementors of this async-trait can be used to drive a MySQL-compatible database backend.
pub trait AsyncMysqlShim<W: Send> {
    /// The error type produced by operations on this shim.
    ///
    /// Must implement `From<io::Error>` so that transport-level errors can be lifted.
    type Error: From<io::Error>;

    /// Admit the next network command before reading its header or payload.
    /// This boundary has no decoded opcode, query ID or statement source.
    ///
    /// A backend condition is written verbatim and flushed before closing the
    /// connection. Operational failures retain `Self::Error`. The default
    /// leaves external shims unchanged and supplies no quota or identity fact.
    async fn before_command_read(&mut self) -> Result<Option<(u16, [u8; 5], String)>, Self::Error> {
        Ok(None)
    }

    /// Observe the actual decoded Classic opcode, before handler lookup.
    /// This hook does not issue a query, execution receipt or control source.
    fn on_command_received(&mut self, _opcode: u8) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Borrows the actual decoded command after its native packet fields are
    /// valid, before execution. QUERY/EXECUTE bindings are decoded first;
    /// malformed packet fields never acquire a command query ordinal.
    /// Implementations reuse this occurrence in SQL/PS callbacks rather than
    /// issuing another ID or retaining a second statement owner.
    async fn on_command_begin(&mut self, _opcode: u8) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Finishes a decoded command without an existing query-finished callback.
    /// SQL/EXECUTE and SQL tails retain their original END; this callback is
    /// not issued in addition to a successful `on_query_finished`.
    /// Connection failures/peer cancellation retain the original disconnect
    /// cleanup instead of fabricating successful command completion here.
    fn on_command_finished(&mut self, _opcode: u8) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Admit an actually parsed command before any command-specific mutation.
    ///
    /// Backends with authenticated session state enforce their command-level
    /// gates here, before SET_OPTION, RESET or other handlers change state.
    /// A native rejection is written as the returned ERR; operational failures
    /// retain `Self::Error` and are not translated into an SQL condition.
    ///
    /// The default preserves external shim behavior. It supplies no principal,
    /// password-expiration fact or privilege proof; a backend requiring those
    /// facts must provide them from its own authenticated session owner.
    async fn command_admission_error(
        &mut self,
        _opcode: u8,
    ) -> Result<Option<(ErrorKind, String)>, Self::Error> {
        Ok(None)
    }

    /// Server version
    fn version(&self) -> String {
        // 5.1.10 because that's what Ruby's ActiveRecord requires
        "5.1.10-alpha-msql-proxy".to_string()
    }

    /// Connection id
    fn connect_id(&self) -> u32 {
        u32::from_le_bytes([0x08, 0x00, 0x00, 0x00])
    }

    /// Character-set/collation id advertised by HandshakeV10.
    ///
    /// 255 is MySQL 8's `utf8mb4_0900_ai_ci`. Backends that expose a
    /// different server default may override this value.
    fn handshake_collation(&self) -> u8 {
        255
    }

    /// Current server status used by protocol-owned OK packets and the
    /// initial HandshakeV10 exchange.
    fn status_flags(&self) -> StatusFlags {
        StatusFlags::SERVER_STATUS_AUTOCOMMIT
    }

    /// get auth plugin
    fn default_auth_plugin(&self) -> &str {
        MYSQL_NATIVE_PASSWORD
    }

    /// Selects a plugin using the original login bytes and packet charset.
    /// `initial_handshake` is true only for HandshakeResponse, false for
    /// COM_CHANGE_USER. A backend uses this actual phase for native name
    /// conversion; it is not credential or privilege evidence.
    async fn auth_plugin_for_username(
        &self,
        _user: &[u8],
        _character_set: u16,
        _initial_handshake: bool,
    ) -> Result<(&'static str, Option<&'static [u8]>), Self::Error> {
        Ok((MYSQL_NATIVE_PASSWORD, None))
    }

    /// Advance only after the backend's current factor was actually accepted.
    /// None preserves the original one-factor path; a returned empty plugin
    /// is an installed server-only method which must fail without a challenge.
    async fn next_authentication_factor(
        &self,
    ) -> Result<Option<(&'static str, &'static [u8])>, Self::Error> {
        Ok(None)
    }

    /// Default salt(scramble) for auth plugin
    fn salt(&self) -> [u8; SCRAMBLE_SIZE] {
        let bs = ";X,po_k}>o6^Wz!/kM}N".as_bytes();
        let mut scramble: [u8; SCRAMBLE_SIZE] = [0; SCRAMBLE_SIZE];
        for i in 0..SCRAMBLE_SIZE {
            scramble[i] = bs[i];
            if scramble[i] == b'\0' || scramble[i] == b'$' {
                scramble[i] += 1;
            }
        }
        scramble
    }

    /// Authenticates with the same raw name, charset and phase used to select
    /// the plugin. The backend, not this transport, owns the canonical name.
    async fn authenticate(
        &self,
        _auth_plugin: &str,
        _username: &[u8],
        _character_set: u16,
        _initial_handshake: bool,
        _salt: &[u8],
        _auth_data: &[u8],
    ) -> bool {
        true
    }

    /// Formats the handshake authentication failure exposed to clients.
    fn authentication_error_message(
        &self,
        username: &[u8],
        _character_set: u16,
        _initial_handshake: bool,
        auth_data: &[u8],
    ) -> String {
        format!(
            "Access denied for user '{}' (using password: {})",
            String::from_utf8_lossy(username),
            if auth_data.is_empty() { "NO" } else { "YES" }
        )
    }

    /// Borrow the first actual authentication DA error for an entered
    /// CHANGE_USER. This never creates a condition or changes controls.
    fn authentication_error_response(&self) -> Option<(u16, [u8; 5], String)> {
        None
    }

    /// Publish this original entered CHANGE_USER failure into the backend's
    /// current diagnostics before writing its ERR. This is not invoked for
    /// handshake, RESET, framing errors or pre-dispatch refusal. A backend
    /// must preserve its already published first error; no message inspection
    /// or errno-based reconstruction of the reached phase is permitted.
    fn on_change_user_error(&mut self, _code: u16, _state: [u8; 5], _message: &str) {}

    /// Maximum command packet accepted by this connection.
    fn max_allowed_packet(&self) -> usize {
        packet_reader::DEFAULT_MAX_ALLOWED_PACKET
    }

    /// Optional caching_sha2_password exchange. Returning `None` keeps the one-packet
    /// authentication path used by mysql_native_password.
    async fn caching_sha2_password_auth(
        &self,
        _username: &[u8],
        _character_set: u16,
        _initial_handshake: bool,
        _salt: &[u8],
        _initial_response: &[u8],
    ) -> Option<CachingSha2PasswordAuth> {
        None
    }

    /// Supplies the RSA key pair used by sha256_password on an unencrypted
    /// connection. The same container is used because both plugins use OAEP
    /// with the handshake scramble; sha256_password has no fast-auth phase.
    async fn sha256_password_auth(
        &self,
        _username: &[u8],
        _character_set: u16,
        _initial_handshake: bool,
        _salt: &[u8],
        _initial_response: &[u8],
    ) -> Option<CachingSha2PasswordAuth> {
        None
    }

    /// Verifies the cleartext candidate produced by caching_sha2_password full
    /// authentication. The protocol layer decrypts the transient candidate but
    /// never receives durable verifier material from the backend.
    async fn authenticate_cleartext(
        &self,
        _auth_plugin: &str,
        _username: &[u8],
        _character_set: u16,
        _initial_handshake: bool,
        _candidate: &[u8],
    ) -> bool {
        false
    }

    /// Records the final result of one credential proof before the protocol
    /// sends its OK or ERR packet. A backend may downgrade a successful proof
    /// for account policy, but a failed proof can never be upgraded.
    async fn on_authentication_result(
        &mut self,
        _username: &[u8],
        _character_set: u16,
        _initial_handshake: bool,
        authenticated: bool,
    ) -> bool {
        authenticated
    }

    /// Supplies read-only facts from the server-side TLS session. Peer
    /// certificates are present only when the configured verifier accepted
    /// the client certificate chain.
    fn on_tls_session(
        &mut self,
        _session: TlsSessionInfo,
        _peer_certificates: &[Vec<u8>],
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Base capabilities supported by the protocol layer before shim-specific additions.
    fn base_capabilities(&self) -> CapabilityFlags {
        CapabilityFlags::CLIENT_PROTOCOL_41
            | CapabilityFlags::CLIENT_SECURE_CONNECTION
            | CapabilityFlags::CLIENT_PLUGIN_AUTH
            | CapabilityFlags::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
            | CapabilityFlags::CLIENT_CONNECT_WITH_DB
            | CapabilityFlags::CLIENT_SESSION_TRACK
            | CapabilityFlags::CLIENT_DEPRECATE_EOF
    }

    /// Let a backend advertise additional capabilities that it can actually handle.
    fn server_capabilities(&self, base: CapabilityFlags) -> CapabilityFlags {
        base
    }

    /// Read the original connection policy once, at its actual greeting.
    /// The returned compression bits and uncompressed permission belong to
    /// that same handshake, even if the backend's GLOBAL value later changes.
    fn handshake_capabilities(&self) -> Result<(CapabilityFlags, bool), Self::Error> {
        Ok((self.server_capabilities(self.base_capabilities()), true))
    }

    /// Opt-in only for a shim implementing the negotiated envelopes below.
    /// The returned permit must be issued by its actual process budget and
    /// remain live until the physical collection or source types are dropped.
    fn query_attributes_admission(&self) -> Option<CommandAllocationAdmission> {
        None
    }

    /// Admit the actual result row/packet buffers before each capacity grows.
    /// The physical buffer keeps the returned permit until it is dropped.
    /// This does not negotiate or authorize query attributes.
    fn result_allocation_admission(&self) -> Option<CommandAllocationAdmission> {
        None
    }

    /// Called after the client handshake has been parsed and before authentication completes.
    fn on_client_capabilities(
        &mut self,
        _capabilities: CapabilityFlags,
        _connection_attrs: &[u8],
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called when COM_SET_OPTION changes a capability after authentication.
    fn on_client_capabilities_changed(&mut self, _capabilities: CapabilityFlags) {}

    /// Replaces connection attributes supplied by a successful COM_CHANGE_USER.
    fn on_change_user_connection_attrs(
        &mut self,
        _connection_attrs: &[u8],
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Validates the actual packet charset before plugin selection. Initial
    /// authentication and COM_CHANGE_USER both call this read-only hook;
    /// CHANGE_USER does not publish a new connection charset before commit.
    /// A backend owns unknown-ID/global fallback, not this metadata resolver.
    fn client_collation_error(
        &self,
        _collation_id: u16,
        _character_set: &str,
        _collation_name: &str,
    ) -> Option<(ErrorKind, String)> {
        None
    }

    /// Records the character set selected in HandshakeResponse41.
    fn on_client_collation(
        &mut self,
        _collation_id: u16,
        _character_set: &str,
        _collation_name: &str,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Reports the compression algorithm selected by the handshake.  Level is
    /// 0 for an uncompressed connection and 6 for the classic zlib default.
    fn on_compression(&mut self, _algorithm: &'static str, _level: u8) {}

    /// Called after authentication succeeds so session-visible identity follows the login user.
    fn on_authenticated_user(
        &mut self,
        _username: &[u8],
        _character_set: u16,
        _initial_handshake: bool,
    ) {
    }

    /// Gives the backend an asynchronous admission-control point after
    /// credentials have been verified but before the handshake OK packet is
    /// sent. Returning an error keeps connection limits and maintenance gates
    /// observable as ordinary MySQL handshake errors.
    async fn authenticated_user_admission_error(
        &mut self,
        _username: &[u8],
        _character_set: u16,
        _initial_handshake: bool,
        _defer_identity_publication: bool,
    ) -> Option<(ErrorKind, String)> {
        None
    }

    /// Lets the backend reject COM_STATISTICS for session-level gates such as
    /// mandatory password replacement. `None` preserves the ordinary status
    /// response.
    async fn statistics_command_error(&mut self) -> Option<(ErrorKind, String)> {
        None
    }

    /// Handles COM_STATISTICS after the authenticated command gate.
    ///
    /// A backend supplies all facts from its actual server and current
    /// command owners. The default refuses missing producers rather than
    /// synthesizing connection uptime or session counters. The writer emits
    /// one text or ERR packet, never a result set, OK or EOF.
    async fn on_statistics<'a>(
        &'a mut self,
        writer: StatisticsWriter<'a, W>,
    ) -> Result<(), Self::Error>
    where
        W: AsyncWrite + Unpin,
    {
        writer
            .error(
                ErrorKind::ER_NOT_SUPPORTED_YET,
                b"COM_STATISTICS global producers are not installed",
            )
            .await
            .map_err(Self::Error::from)
    }

    /// Called when the client issues a request to prepare `query` for later execution.
    ///
    /// The provided [`StatementMetaWriter`](struct.StatementMetaWriter.html) should be used to
    /// notify the client of the statement id assigned to the prepared statement, as well as to
    /// give metadata about the types of parameters and returned columns.
    async fn on_prepare<'a>(
        &'a mut self,
        query: &'a [u8],
        info: StatementMetaWriter<'a, W>,
    ) -> Result<(), Self::Error>;

    /// Called when the client executes a previously prepared statement.
    ///
    /// Any parameters included with the client's command is given in `params`.
    /// A response to the query should be given using the provided
    /// [`QueryResultWriter`](struct.QueryResultWriter.html).
    async fn on_execute<'a>(
        &'a mut self,
        id: u32,
        params: ParamParser<'a>,
        results: QueryResultWriter<'a, W>,
    ) -> Result<(), Self::Error>;

    /// Called when COM_STMT_RESET clears long data and cursor state. Native
    /// source parameter types remain available for a later reuse execution.
    async fn on_reset_statement(&mut self, _stmt: u32) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called for a cursor execute. Backends that support cursors should retain the result and
    /// reply with SERVER_STATUS_CURSOR_EXISTS instead of sending all rows immediately.
    async fn on_execute_cursor<'a>(
        &'a mut self,
        id: u32,
        params: ParamParser<'a>,
        results: QueryResultWriter<'a, W>,
    ) -> Result<(), Self::Error> {
        self.on_execute(id, params, results).await
    }

    /// A negotiated packet with its complete ordered raw bindings. There is
    /// no default that discards attributes or turns them into placeholders.
    async fn on_execute_bindings<'a>(
        &'a mut self,
        _id: u32,
        _bindings: ParsedBindings<'a>,
        results: QueryResultWriter<'a, W>,
    ) -> Result<(), Self::Error>
    where
        W: AsyncWrite + Unpin,
    {
        results
            .error(
                ErrorKind::ER_NOT_SUPPORTED_YET,
                b"negotiated query bindings require an installed command consumer",
            )
            .await
            .map_err(Self::Error::from)
    }

    /// Called by COM_STMT_FETCH for an open read-only cursor.
    async fn on_fetch<'a>(
        &'a mut self,
        _stmt: u32,
        _rows: u32,
        results: QueryResultWriter<'a, W>,
    ) -> Result<(), Self::Error>
    where
        W: AsyncWrite + Unpin,
    {
        results
            .error(
                ErrorKind::ER_STMT_HAS_NO_OPEN_CURSOR,
                b"statement has no open cursor",
            )
            .await
            .map_err(Self::Error::from)
    }

    /// Called by COM_RESET_CONNECTION after protocol-owned statement state has been cleared.
    async fn on_reset_connection(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Enter a decoded COM_CHANGE_USER before parsing its fields or authenticating.
    /// Retire the old connection's application state in place. This is distinct
    /// from RESET CONNECTION and is not called for transport/framing failures.
    async fn on_change_user_begin(
        &mut self,
    ) -> Result<Option<(u16, [u8; 5], String)>, Self::Error> {
        Ok(None)
    }

    /// Install a successfully authenticated COM_CHANGE_USER request. A rejected
    /// entered request sends one ERR, flushes it and terminates this connection.
    async fn on_change_user(
        &mut self,
        username: &[u8],
        database: Option<&[u8]>,
        character_set: u16,
    ) -> Result<Option<(ErrorKind, String)>, Self::Error> {
        let _ = (username, database, character_set);
        Ok(None)
    }

    /// Called when the client wishes to deallocate resources associated with a previously prepared
    /// statement.
    async fn on_close<'a>(&'a mut self, stmt: u32)
    where
        W: 'async_trait;

    /// Called when the client issues a query for immediate execution.
    ///
    /// Results should be returned using the given
    /// [`QueryResultWriter`](struct.QueryResultWriter.html).
    async fn on_query<'a>(
        &'a mut self,
        query: &'a [u8],
        results: QueryResultWriter<'a, W>,
    ) -> Result<(), Self::Error>;

    /// The actual COM_PROCESS_INFO packet. This is always the backend's
    /// legacy short producer, never a SQL source or GLOBAL SHOW policy.
    async fn on_process_info<'a>(
        &'a mut self,
        results: QueryResultWriter<'a, W>,
    ) -> Result<(), Self::Error>
    where
        W: AsyncWrite + Unpin,
    {
        results
            .error(
                ErrorKind::ER_NOT_SUPPORTED_YET,
                b"COM_PROCESS_INFO callback is not installed",
            )
            .await
            .map_err(Self::Error::from)
    }

    async fn on_query_bindings<'a>(
        &'a mut self,
        _bindings: ParsedBindings<'a>,
        results: QueryResultWriter<'a, W>,
    ) -> Result<(), Self::Error>
    where
        W: AsyncWrite + Unpin,
    {
        results
            .error(
                ErrorKind::ER_NOT_SUPPORTED_YET,
                b"negotiated query bindings require an installed command consumer",
            )
            .await
            .map_err(Self::Error::from)
    }

    /// Called before LOCAL admission on the same command owner. The default
    /// handles no attributes; an attribute-capable LOCAL consumer must retain
    /// the actual command payload, not a Session name map.
    async fn preflight_local_infile_with_bindings<'writer>(
        &mut self,
        bindings: &ParsedBindings<'_>,
        client_supports_local: bool,
        results: QueryResultWriter<'writer, W>,
    ) -> Result<LocalInfilePreflight<'writer, W>, Self::Error> {
        if !bindings.slots().is_empty() {
            return Ok(LocalInfilePreflight::Continue(results));
        }
        self.preflight_local_infile(bindings.suffix(), client_supports_local, results)
            .await
    }

    /// Called after an in-flight query future is dropped because the peer disconnected or sent a
    /// new command before consuming the current response. Implementations should release
    /// statement-scoped resources; dropping the query future remains the primary cancellation
    /// signal for execution streams.
    async fn on_query_cancelled(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called after a text or prepared query response has completed.
    async fn on_query_finished(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called exactly once after the command loop stops, whether by COM_QUIT,
    /// peer disconnect, idle timeout, malformed input, or transport failure.
    async fn on_disconnect(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Resolves when an administrator has requested teardown of this
    /// connection. The command loop flushes any completed response before it
    /// observes this signal on the next read boundary.
    fn connection_shutdown(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(std::future::pending())
    }

    /// Maximum time to wait between commands. `None` disables protocol-owned
    /// idle timeout handling.
    fn idle_timeout(&self) -> Option<std::time::Duration> {
        None
    }

    fn network_settings(&self) -> Option<NetworkSettings> {
        None
    }

    /// Runs after the successful authentication response, before the first command.
    /// A failure is delivered on that command boundary, never as a false auth failure.
    async fn initialize_connection(&mut self) -> Option<(ErrorKind, String)> {
        None
    }

    /// Called when the client asks for field metadata using COM_FIELD_LIST.
    ///
    /// mysql CLI uses this deprecated command while loading table-completion
    /// metadata for interactive sessions.
    async fn on_list_fields<'a>(
        &'a mut self,
        _payload: &'a [u8],
        results: QueryResultWriter<'a, W>,
    ) -> Result<(), Self::Error>
    where
        W: AsyncWrite + Unpin,
    {
        results.field_list(&[]).await?;
        Ok(())
    }

    /// Parse and authorize a possible LOCAL request before the protocol sends
    /// 0xfb. Capability absence is an admission fact, not permission to skip
    /// parsing and silently reinterpret the command as ordinary SQL.
    async fn preflight_local_infile<'writer>(
        &mut self,
        _query: &[u8],
        _client_supports_local: bool,
        results: QueryResultWriter<'writer, W>,
    ) -> Result<LocalInfilePreflight<'writer, W>, Self::Error> {
        Ok(LocalInfilePreflight::Continue(results))
    }

    /// Called for each LOCAL INFILE data packet.
    async fn on_local_infile_data<'a>(&'a mut self, _data: &'a [u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Discard an in-progress LOCAL INFILE transfer after the protocol layer
    /// rejects its payload. The reader drains through the terminating packet
    /// before invoking this callback, so the next command stays synchronized.
    async fn on_local_infile_abort(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called after the terminating empty LOCAL INFILE packet.
    async fn on_local_infile_end<'a>(
        &'a mut self,
        results: QueryResultWriter<'a, W>,
    ) -> Result<(), Self::Error> {
        let _ = results;
        Ok(())
    }

    /// Called when the client switches database, borrowing the original
    /// COM_INIT_DB bytes. The backend owns connection-charset conversion,
    /// database validation, and any SQL error response.
    async fn on_init<'a>(
        &'a mut self,
        _: &'a [u8],
        _: InitWriter<'a, W>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Borrows the original database bytes carried by HandshakeResponse41.
    /// The backend owns bounded native system-charset conversion. This is distinct
    /// from COM_INIT_DB because an account admitted solely to recover an
    /// expired password must be allowed to finish connecting in sandbox mode.
    /// Return false after writing the one SQL rejection response. The transport
    /// flushes it and closes before initialization or command dispatch. Shims
    /// which reject database admission must override this callback; the default
    /// delegates the existing on_init behavior and accepts its successful return.
    async fn on_initial_database<'a>(
        &'a mut self,
        database: &'a [u8],
        writer: InitWriter<'a, W>,
    ) -> Result<bool, Self::Error> {
        self.on_init(database, writer).await?;
        Ok(true)
    }
}

#[derive(Clone, Debug)]
pub struct CachingSha2PasswordAuth {
    /// Borrow the process-owned (private, public) PEM pair only when the
    /// exchange actually sends a public key or decrypts an RSA response.
    pub rsa_keys: fn() -> (&'static str, &'static str),
    /// Skip the cached verifier and exercise the full cleartext/TLS or RSA exchange.
    /// This is primarily useful for deterministic protocol conformance tests.
    pub force_full_auth: bool,
}

/// The options which passed to AsyncMysqlIntermediary struct
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntermediaryOptions {
    /// process use statement on the on_query handler
    pub process_use_statement_on_query: bool,
    /// reject connection if dbname not provided
    pub reject_connection_on_dbname_absence: bool,
}

#[derive(Default)]
struct StatementData {
    long_data: HashMap<u16, Vec<u8>>,
    long_data_error: Option<ErrorKind>,
    bound_types: Vec<(u16, bool)>,
    type_allocation: Option<CommandAllocation>,
    params: u16,
}

#[derive(Debug, PartialEq, Eq)]
struct ChangeUserRequest<'a> {
    username: &'a [u8],
    auth_data: &'a [u8],
    database: Option<&'a [u8]>,
    character_set: u16,
    plugin: Option<&'a str>,
    connection_attrs: &'a [u8],
}

fn parse_change_user_native<'a>(
    payload: &'a [u8],
    capabilities: CapabilityFlags,
) -> Result<ChangeUserRequest<'a>, (io::Error, Option<ErrorKind>)> {
    // One original parser body. The outcome carries only its reached native
    // failure phase: explicit field errors versus attributes' unset DA.
    let mut first_error = Some(ErrorKind::ER_UNKNOWN_COM_ERROR);
    let parsed: io::Result<ChangeUserRequest<'a>> = (|| {
        let (username, rest) = take_nul_terminated(payload, "COM_CHANGE_USER username")?;
        // COM_CHANGE_USER has a one-byte auth length, independently of the
        // HandshakeResponse41 LENENC_CLIENT_DATA capability.
        let (&len, rest) = rest.split_first().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "COM_CHANGE_USER missing auth length",
            )
        })?;
        let (auth_data, rest) =
            take_bytes(rest, usize::from(len), "COM_CHANGE_USER auth response")?;
        let (database, rest) = take_nul_terminated(rest, "COM_CHANGE_USER database")?;
        let (character_set, mut rest) = take_bytes(rest, 2, "COM_CHANGE_USER character set")?;
        let character_set = u16::from_le_bytes([character_set[0], character_set[1]]);
        let plugin = if capabilities.contains(CapabilityFlags::CLIENT_PLUGIN_AUTH) {
            let (plugin, remaining) = take_nul_terminated(rest, "COM_CHANGE_USER auth plugin")?;
            rest = remaining;
            let plugin = std::str::from_utf8(plugin)
                .map_err(|_| invalid_data("COM_CHANGE_USER auth plugin is not UTF-8"))?;
            (!plugin.is_empty()).then_some(plugin)
        } else {
            None
        };
        let mut connection_attrs = &[][..];
        if capabilities.contains(CapabilityFlags::CLIENT_CONNECT_ATTRS) {
            // Native read_client_connect_attrs returns failure without setting DA.
            first_error = None;
            let (length, attributes) =
                read_lenenc_int(rest, "COM_CHANGE_USER connection attributes")?;
            if length > 65_535 {
                return Err(invalid_data(
                    "COM_CHANGE_USER connection attributes exceed 65535 bytes",
                ));
            }
            let (attributes, remaining) =
                take_bytes(attributes, length, "COM_CHANGE_USER connection attributes")?;
            if !remaining.is_empty() {
                return Err(invalid_data("COM_CHANGE_USER contains trailing bytes"));
            }
            connection_attrs = attributes;
        } else if !rest.is_empty() {
            return Err(invalid_data("COM_CHANGE_USER contains trailing bytes"));
        }
        Ok(ChangeUserRequest {
            username,
            auth_data,
            database: (!database.is_empty()).then_some(database),
            character_set,
            plugin,
            connection_attrs,
        })
    })();
    parsed.map_err(|error| (error, first_error))
}
fn take_nul_terminated<'a>(
    input: &'a [u8],
    field: &'static str,
) -> io::Result<(&'a [u8], &'a [u8])> {
    let end = input
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| invalid_data(format!("{field} is not NUL terminated")))?;
    Ok((&input[..end], &input[end + 1..]))
}

fn take_bytes<'a>(
    input: &'a [u8],
    length: usize,
    field: &'static str,
) -> io::Result<(&'a [u8], &'a [u8])> {
    if input.len() < length {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("truncated {field}"),
        ));
    }
    Ok(input.split_at(length))
}

fn read_lenenc_int<'a>(input: &'a [u8], field: &'static str) -> io::Result<(usize, &'a [u8])> {
    let (&prefix, rest) = input
        .split_first()
        .ok_or_else(|| invalid_data(format!("{field} length is missing")))?;
    let (value, rest) = match prefix {
        0x00..=0xfa => (u64::from(prefix), rest),
        0xfb => return Err(invalid_data(format!("{field} length cannot be NULL"))),
        0xfc => {
            let (bytes, rest) = take_bytes(rest, 2, field)?;
            (u64::from(u16::from_le_bytes([bytes[0], bytes[1]])), rest)
        }
        0xfd => {
            let (bytes, rest) = take_bytes(rest, 3, field)?;
            (
                u64::from(bytes[0]) | (u64::from(bytes[1]) << 8) | (u64::from(bytes[2]) << 16),
                rest,
            )
        }
        0xfe | 0xff => {
            let (bytes, rest) = take_bytes(rest, 8, field)?;
            (
                u64::from_le_bytes(bytes.try_into().expect("length checked above")),
                rest,
            )
        }
    };
    let value = usize::try_from(value)
        .map_err(|_| invalid_data(format!("{field} length exceeds this server")))?;
    Ok((value, rest))
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn mysql_refresh_query(flags: u8) -> Option<String> {
    // COM_REFRESH has one response even when several bits are set. Route the
    // request through one representative FLUSH statement; the product layer
    // applies the shared implicit-commit contract and treats the operational
    // targets as acknowledged no-ops.
    (flags != 0).then(|| "FLUSH TABLES".to_string())
}

const AUTH_PLUGIN_DATA_PART_1_LENGTH: usize = 8;

/// A server that speaks the MySQL/MariaDB protocol, and can delegate client commands to a backend
/// that implements [`AsyncMysqlShim`](trait.AsyncMysqlShim.html).
pub struct AsyncMysqlIntermediary<B, S: AsyncRead + Unpin, W> {
    pub(crate) client_capabilities: CapabilityFlags,
    process_use_statement_on_query: bool,
    reject_connection_on_dbname_absence: bool,
    shim: B,
    reader: packet_reader::PacketReader<S>,
    writer: packet_writer::PacketWriter<W>,
    zstd_compression_level: u8,
    secure_transport: bool,
    uncompressed_allowed: bool,
}

/// Configuration used to craft the initial server handshake before a shim is available.
#[derive(Clone, Debug)]
pub struct ServerHandshakeConfig {
    pub version: String,
    pub connection_id: u32,
    pub default_auth_plugin: String,
    pub scramble: [u8; SCRAMBLE_SIZE],
    pub server_capabilities: CapabilityFlags,
    pub uncompressed_allowed: bool,
    pub collation: u8,
    pub status_flags: StatusFlags,
}

impl<B, R, W> AsyncMysqlIntermediary<B, R, W>
where
    W: AsyncWrite + Send + Unpin,
    B: AsyncMysqlShim<W> + Send + Sync,
    R: AsyncRead + Send + Unpin,
{
    /// Create a new server over two one-way channels and process client commands until the client
    /// disconnects or an error occurs.
    pub async fn run_on(shim: B, stream: R, output_stream: W) -> Result<(), B::Error> {
        Self::run_with_options(shim, stream, output_stream, &Default::default()).await
    }

    /// Create a new server over two one-way channels and process client commands until the client
    /// disconnects or an error occurs, with config options.
    pub async fn run_with_options(
        mut shim: B,
        input_stream: R,
        mut output_stream: W,
        opts: &IntermediaryOptions,
    ) -> Result<(), B::Error> {
        let process_use_statement_on_query = opts.process_use_statement_on_query;
        let reject_connection_on_dbname_absence = opts.reject_connection_on_dbname_absence;
        let (_, (handshake, seq, client_capabilities, uncompressed_allowed, input_stream)) =
            AsyncMysqlIntermediary::init_before_ssl(
                &mut shim,
                input_stream,
                &mut output_stream,
                #[cfg(feature = "tls")]
                &None,
            )
            .await?;

        let reader = PacketReader::new(input_stream);
        let writer = PacketWriter::new(output_stream);

        let mut mi = AsyncMysqlIntermediary {
            client_capabilities,
            process_use_statement_on_query,
            reject_connection_on_dbname_absence,
            shim,
            reader,
            writer,
            zstd_compression_level: 0,
            secure_transport: false,
            uncompressed_allowed,
        };
        if let Err(error) = mi.init_after_ssl(handshake, seq).await {
            let _ = mi.shim.on_disconnect().await;
            return Err(error);
        }
        // libmysql uses the legacy zlib protocol whenever CLIENT_COMPRESS is
        // present, even if CLIENT_ZSTD_COMPRESSION_ALGORITHM is also set by a
        // multi-value --compression-algorithms option.
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

    pub async fn init_before_ssl(
        shim: &mut B,
        input_stream: R,
        output_stream: &mut W,
        #[cfg(feature = "tls")] tls_conf: &Option<std::sync::Arc<ServerConfig>>,
    ) -> Result<
        (
            bool,
            (ClientHandshake, u8, CapabilityFlags, bool, PacketReader<R>),
        ),
        B::Error,
    > {
        let (capabilities, uncompressed_allowed) = shim.handshake_capabilities()?;
        let config = ServerHandshakeConfig {
            version: shim.version(),
            connection_id: shim.connect_id(),
            default_auth_plugin: shim.default_auth_plugin().to_string(),
            scramble: shim.salt(),
            server_capabilities: query_attribute_capabilities(
                capabilities,
                shim.query_attributes_admission().is_some(),
            ),
            uncompressed_allowed,
            collation: shim.handshake_collation(),
            status_flags: shim.status_flags(),
        };

        AsyncMysqlIntermediary::<B, R, W>::init_before_ssl_with_config(
            &config,
            input_stream,
            output_stream,
            #[cfg(feature = "tls")]
            tls_conf,
        )
        .await
        .map_err(B::Error::from)
    }

    pub async fn init_before_ssl_with_config(
        config: &ServerHandshakeConfig,
        input_stream: R,
        output_stream: &mut W,
        #[cfg(feature = "tls")] tls_conf: &Option<std::sync::Arc<ServerConfig>>,
    ) -> io::Result<(
        bool,
        (ClientHandshake, u8, CapabilityFlags, bool, PacketReader<R>),
    )> {
        let mut reader = PacketReader::new(input_stream);
        let mut writer = PacketWriter::new(output_stream);
        // https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeV10
        writer.write_all(&[10])?; // protocol 10

        writer.write_all(config.version.as_bytes())?;
        writer.write_all(&[0x00])?;

        // connection_id (4 bytes)
        writer.write_all(&config.connection_id.to_le_bytes())?;

        let mut server_capabilities = config.server_capabilities;
        // A backend bit is not a TLS context. Only this actual transport
        // configuration may advertise or accept the SSLRequest transition.
        server_capabilities.remove(CapabilityFlags::CLIENT_SSL);
        #[cfg(feature = "tls")]
        let ssl_available = tls_conf.is_some();
        #[cfg(not(feature = "tls"))]
        let ssl_available = false;
        if ssl_available {
            server_capabilities.insert(CapabilityFlags::CLIENT_SSL);
        }

        let server_capabilities_vec = server_capabilities.bits().to_le_bytes();
        let default_auth_plugin = config.default_auth_plugin.as_str();
        let scramble = &config.scramble;

        writer.write_all(&scramble[0..AUTH_PLUGIN_DATA_PART_1_LENGTH])?; // auth-plugin-data-part-1
        writer.write_all(&[0x00])?;

        writer.write_all(&server_capabilities_vec[..2])?; // The lower 2 bytes of the Capabilities Flags, 0x42
        // self.writer.write_all(&[0x00, 0x42])?;
        writer.write_all(&[config.collation])?;
        writer.write_all(&config.status_flags.bits().to_le_bytes())?;
        writer.write_all(&server_capabilities_vec[2..4])?; // The upper 2 bytes of the Capabilities Flags

        if default_auth_plugin.is_empty() {
            // no plugins
            writer.write_all(&[0x00])?;
        } else {
            writer.write_all(&((scramble.len() + 1) as u8).to_le_bytes())?; // length of the combined auth_plugin_data(scramble), if auth_plugin_data_len is > 0
        }
        writer.write_all(&[0x00; 10][..])?; // 10 bytes filler

        // Part2 of the auth_plugin_data
        // $len=MAX(13, length of auth-plugin-data - 8)
        writer.write_all(&scramble[AUTH_PLUGIN_DATA_PART_1_LENGTH..])?; // 12 bytes
        writer.write_all(&[0x00])?;

        // Plugin name
        writer.write_all(default_auth_plugin.as_bytes())?;
        writer.write_all(&[0x00])?;
        writer.end_packet().await?;
        writer.flush_all().await?;

        let (seq, handshake) = reader
            .next_async_in_exchange(writer.sequence())
            .await?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "peer terminated connection",
                )
            })?;

        let handshake = commands::client_handshake(&handshake, false, server_capabilities)
            .map_err(|e| match e {
                nom::Err::Incomplete(_) => io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client sent incomplete handshake",
                ),
                nom::Err::Failure(nom_error) | nom::Err::Error(nom_error) => {
                    if let nom::error::ErrorKind::Eof = nom_error.code {
                        io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "client did not complete handshake",
                        )
                    } else {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("bad client handshake ({:?})", nom_error.code),
                        )
                    }
                }
            })?
            .1;

        writer.set_seq(seq.wrapping_add(1));

        if handshake.capabilities.contains(CapabilityFlags::CLIENT_SSL) {
            if !ssl_available {
                writers::write_err(ErrorKind::ER_HANDSHAKE_ERROR, b"Bad handshake", &mut writer)
                    .await?;
                writer.flush_all().await?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "client requested SSL without an actual TLS context",
                )
                .into());
            }
            return Ok((
                true,
                (
                    handshake,
                    seq,
                    server_capabilities,
                    config.uncompressed_allowed,
                    reader,
                ),
            ));
        }

        Ok((
            false,
            (
                handshake,
                seq,
                server_capabilities,
                config.uncompressed_allowed,
                reader,
            ),
        ))
    }

    pub async fn init_after_ssl(
        &mut self,
        #[cfg(feature = "tls")] mut handshake: ClientHandshake,
        #[cfg(not(feature = "tls"))] handshake: ClientHandshake,
        mut seq: u8,
    ) -> Result<(), B::Error> {
        let settings = self.shim.network_settings();
        self.reader.set_network_settings(settings.clone());
        self.writer.set_network_settings(settings);
        self.writer
            .set_allocation_admission(self.shim.result_allocation_admission());
        if handshake.capabilities.contains(CapabilityFlags::CLIENT_SSL) && !self.secure_transport {
            self.writer.set_seq(seq.wrapping_add(1));
            writers::write_err(
                ErrorKind::ER_HANDSHAKE_ERROR,
                b"Bad handshake",
                &mut self.writer,
            )
            .await?;
            self.writer.flush_all().await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SSLRequest did not enter the actual TLS transport",
            )
            .into());
        }
        #[cfg(feature = "tls")]
        if handshake.capabilities.contains(CapabilityFlags::CLIENT_SSL) {
            let (_seq, hs) = self
                .reader
                .next_async_in_exchange(seq.wrapping_add(1))
                .await?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "peer terminated connection",
                    )
                })?;
            seq = _seq;

            handshake = commands::client_handshake(&hs, true, self.client_capabilities)
                .map_err(|e| match e {
                    nom::Err::Incomplete(_) => io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "client sent incomplete handshake",
                    ),
                    nom::Err::Failure(nom_error) | nom::Err::Error(nom_error) => {
                        if let nom::error::ErrorKind::Eof = nom_error.code {
                            io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "client did not complete handshake",
                            )
                        } else {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("bad client handshake ({:?})", nom_error.code),
                            )
                        }
                    }
                })?
                .1;
        }

        // The temporary pre-TLS writer is discarded after the initial
        // handshake. Continue the connection packet sequence on the writer
        // that owns all authentication and error responses, including errors
        // rejected before the authentication plugin exchange begins.
        self.writer.set_seq(seq.wrapping_add(1));

        let scramble = self.shim.salt();
        {
            if !handshake
                .capabilities
                .contains(CapabilityFlags::CLIENT_PROTOCOL_41)
            {
                let err = io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "Required capability: CLIENT_PROTOCOL_41, please upgrade your MySQL client version",
                );
                return Err(err.into());
            }

            let negotiated_capabilities = handshake.capabilities & self.client_capabilities;
            self.client_capabilities = negotiated_capabilities;
            let client_collation = myc::collations::Collation::resolve(
                myc::collations::CollationId::from(handshake.collation),
            );
            if let Some((kind, message)) = self.shim.client_collation_error(
                handshake.collation,
                client_collation.charset,
                client_collation.collation,
            ) {
                writers::write_err(kind, message.as_bytes(), &mut self.writer).await?;
                self.writer.flush_all().await?;
                return Err(io::Error::new(io::ErrorKind::InvalidInput, message).into());
            }
            self.shim.on_client_collation(
                handshake.collation,
                client_collation.charset,
                client_collation.collation,
            )?;
            self.shim
                .on_client_capabilities(negotiated_capabilities, &handshake.connection_attrs)?;
            self.reader
                .set_max_allowed_packet(self.shim.max_allowed_packet());
            let (compression_algorithm, compression_level) = if negotiated_capabilities
                .contains(CapabilityFlags::CLIENT_COMPRESS)
            {
                ("zlib", 6)
            } else if negotiated_capabilities
                .contains(CapabilityFlags::CLIENT_ZSTD_COMPRESSION_ALGORITHM)
            {
                // Validate only the algorithm actually selected by both
                // peers. Native zlib preference ignores a zstd level, but
                // negotiated zstd requires its real handshake byte.
                let Some(level @ 1..=22) = handshake.zstd_compression_level else {
                    let message = "Invalid zstd compression level for algorithm 'zstd'.";
                    writers::write_err(
                        ErrorKind::ER_WRONG_COMPRESSION_LEVEL_CLIENT,
                        message.as_bytes(),
                        &mut self.writer,
                    )
                    .await?;
                    self.writer.flush_all().await?;
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted, message).into());
                };
                self.zstd_compression_level = level;
                ("zstd", level)
            } else {
                ("", 0)
            };
            // Native parses compression before the authentication plugin
            // completes. A rejected choice cannot publish an authenticated
            // identity, an account lease, or selected compression facts.
            if compression_algorithm.is_empty() && !self.uncompressed_allowed {
                let message = "Invalid compression algorithm 'uncompressed'.";
                writers::write_err(
                    ErrorKind::ER_WRONG_COMPRESSION_ALGORITHM_CLIENT,
                    message.as_bytes(),
                    &mut self.writer,
                )
                .await?;
                self.writer.flush_all().await?;
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, message).into());
            }
            self.shim
                .on_compression(compression_algorithm, compression_level);
            if let Some(username) = &handshake.username {
                let client_plugin = std::str::from_utf8(&handshake.auth_plugin).ok();
                let exchange = self
                    .authenticate_exchange(
                        username,
                        handshake.collation,
                        true,
                        client_plugin,
                        &scramble,
                        (seq, &handshake.auth_response),
                    )
                    .await;
                let (authenticated, auth_seq, used_password) = match exchange {
                    Ok(result) => result,
                    Err(error) => {
                        self.apply_authentication_result(
                            username,
                            handshake.collation,
                            true,
                            false,
                        )
                        .await;
                        return Err(error);
                    }
                };
                let authenticated = self
                    .apply_authentication_result(username, handshake.collation, true, authenticated)
                    .await;
                seq = auth_seq;

                self.writer.set_seq(seq.wrapping_add(1));
                if !authenticated {
                    let password_marker = if used_password { &[1][..] } else { &[][..] };
                    let err_msg = self.shim.authentication_error_message(
                        username,
                        handshake.collation,
                        true,
                        password_marker,
                    );
                    if let Some((code, state, message)) = self.shim.authentication_error_response()
                    {
                        writers::write_err_raw(code, &state, message.as_bytes(), &mut self.writer)
                            .await?;
                    } else {
                        writers::write_err(
                            ErrorKind::ER_ACCESS_DENIED_ERROR,
                            err_msg.as_bytes(),
                            &mut self.writer,
                        )
                        .await?;
                    }
                    self.writer.flush_all().await?;
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, err_msg).into());
                }
                self.shim
                    .on_authenticated_user(username, handshake.collation, true);

                if let Some((kind, message)) = self
                    .shim
                    .authenticated_user_admission_error(
                        username,
                        handshake.collation,
                        true,
                        handshake.db.is_some() || self.reject_connection_on_dbname_absence,
                    )
                    .await
                {
                    writers::write_err(kind, message.as_bytes(), &mut self.writer).await?;
                    self.writer.flush_all().await?;
                    return Err(io::Error::new(io::ErrorKind::ConnectionRefused, message).into());
                }

                let mut needs_default_ok = true;

                if let Some(db_bytes) = handshake.db.as_ref() {
                    let w = InitWriter {
                        client_capabilities: self.client_capabilities,
                        writer: &mut self.writer,
                    };
                    if !self.shim.on_initial_database(db_bytes, w).await? {
                        self.writer.flush_all().await?;
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "initial database admission rejected",
                        )
                        .into());
                    }
                    needs_default_ok = false;
                } else if self.reject_connection_on_dbname_absence {
                    writers::write_err(
                        ErrorKind::ER_DATABASE_NAME,
                        "database required on connection".as_bytes(),
                        &mut self.writer,
                    )
                    .await?;
                    self.writer.flush_all().await?;
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "database name requried: please add db name to the connection",
                    )
                    .into());
                }

                if needs_default_ok {
                    writers::write_ok_packet(
                        &mut self.writer,
                        self.client_capabilities,
                        OkResponse {
                            status_flags: self.shim.status_flags(),
                            ..OkResponse::default()
                        },
                    )
                    .await?;
                }
            }

            self.writer.flush_all().await?;
        };

        Ok(())
    }

    async fn authenticate_exchange(
        &mut self,
        username: &[u8],
        character_set: u16,
        initial_handshake: bool,
        client_plugin: Option<&str>,
        salt: &[u8],
        initial_packet: (u8, &[u8]),
    ) -> Result<(bool, u8, bool), B::Error> {
        let (mut seq, initial_response) = initial_packet;
        let (expected, initial_data) = self
            .shim
            .auth_plugin_for_username(username, character_set, initial_handshake)
            .await?;
        let mut response = initial_response.to_vec();
        let mut used_password = auth_response_uses_password(&response);
        let caching_sha2 = if expected == "caching_sha2_password" {
            self.shim
                .caching_sha2_password_auth(
                    username,
                    character_set,
                    initial_handshake,
                    salt,
                    &response,
                )
                .await
        } else {
            None
        };
        let sha256 = if expected == "sha256_password" {
            self.shim
                .sha256_password_auth(username, character_set, initial_handshake, salt, &response)
                .await
        } else {
            None
        };
        let mut empty_password_authenticated = if expected == "caching_sha2_password"
            && response.is_empty()
            && client_plugin == Some(expected)
        {
            Some(
                self.shim
                    .authenticate(
                        expected,
                        username,
                        character_set,
                        initial_handshake,
                        salt,
                        &response,
                    )
                    .await,
            )
        } else {
            None
        };
        // libmysqlclient begins COM_CHANGE_USER with a zero-length probe even
        // when its caller supplied a password.  That probe is not credential
        // evidence: always request a fresh response for a known SHA2 account,
        // including an account whose stored password is empty.  Unknown
        // accounts still fail immediately; challenging them leaves both peers
        // waiting for a packet that the client will not send.  The normal
        // empty-password proof is one NUL byte, not a zero-length probe.
        let needs_empty_response_switch = response.is_empty()
            && client_plugin == Some(expected)
            && (caching_sha2.is_some() || sha256.is_some());
        if !expected.is_empty()
            && (client_plugin != Some(expected)
                || needs_empty_response_switch
                || initial_data.is_some_and(|data| !data.is_empty()))
        {
            self.writer.set_seq(seq.wrapping_add(1));
            self.writer.write_all(&[0xfe])?;
            self.writer.write_all(expected.as_bytes())?;
            self.writer.write_all(&[0x00])?;
            self.writer.write_all(initial_data.unwrap_or(salt))?;
            if initial_data.is_none() {
                self.writer.write_all(&[0x00])?;
            }
            self.writer.end_packet().await?;
            self.writer.flush_all().await?;
            let (response_seq, switched_response) = self
                .reader
                .next_async_in_exchange(self.writer.sequence())
                .await?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "peer terminated authentication switch",
                    )
                })?;
            seq = response_seq;
            self.writer
                .set_compressed_sequence(self.reader.compressed_sequence());
            response = switched_response.to_vec();
            empty_password_authenticated = None;
            used_password |= auth_response_uses_password(&response);
        }

        self.writer.set_seq(seq.wrapping_add(1));
        // Plugin switching can replace the proof used to select the exchange.
        let caching_sha2 = if expected == "caching_sha2_password" {
            self.shim
                .caching_sha2_password_auth(
                    username,
                    character_set,
                    initial_handshake,
                    salt,
                    &response,
                )
                .await
        } else {
            None
        };
        let authenticated =
            if expected == "caching_sha2_password" && !auth_response_uses_password(&response) {
                // Empty-password clients have finished the plugin exchange. Validate
                // the proof and send only the final OK/ERR, never AuthMoreData.
                used_password = false;
                match empty_password_authenticated {
                    Some(authenticated) => authenticated,
                    None => {
                        self.shim
                            .authenticate(
                                expected,
                                username,
                                character_set,
                                initial_handshake,
                                salt,
                                &response,
                            )
                            .await
                    }
                }
            } else if let Some(caching_sha2) = caching_sha2 {
                if !caching_sha2.force_full_auth
                    && self
                        .shim
                        .authenticate(
                            expected,
                            username,
                            character_set,
                            initial_handshake,
                            salt,
                            &response,
                        )
                        .await
                {
                    self.writer.write_all(&[0x01, 0x03])?;
                    self.writer.end_packet().await?;
                    self.writer.flush_all().await?;
                    seq = seq.wrapping_add(1);
                    true
                } else {
                    self.writer.write_all(&[0x01, 0x04])?;
                    self.writer.end_packet().await?;
                    self.writer.flush_all().await?;
                    let (response_seq, full_response) = self
                        .reader
                        .next_async_in_exchange(self.writer.sequence())
                        .await?
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "peer terminated caching_sha2_password authentication",
                            )
                        })?;
                    seq = response_seq;
                    self.writer
                        .set_compressed_sequence(self.reader.compressed_sequence());
                    let mut rsa_keys = None;
                    let full_response = if full_response.as_ref() == [0x02] {
                        let keys = (caching_sha2.rsa_keys)();
                        rsa_keys = Some(keys);
                        self.writer.set_seq(seq.wrapping_add(1));
                        self.writer.write_all(&[0x01])?;
                        self.writer.write_all(keys.1.as_bytes())?;
                        self.writer.end_packet().await?;
                        self.writer.flush_all().await?;
                        let (encrypted_seq, encrypted) = self
                            .reader
                            .next_async_in_exchange(self.writer.sequence())
                            .await?
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::ConnectionAborted,
                                    "peer terminated RSA authentication",
                                )
                            })?;
                        seq = encrypted_seq;
                        self.writer
                            .set_compressed_sequence(self.reader.compressed_sequence());
                        encrypted.to_vec()
                    } else {
                        full_response.to_vec()
                    };
                    used_password |= full_response.len() > 1;
                    let candidate = decode_caching_sha2_full_auth(
                        || rsa_keys.unwrap_or_else(|| (caching_sha2.rsa_keys)()).0,
                        salt,
                        &full_response,
                        self.secure_transport,
                    );
                    match candidate {
                        Some(candidate) => {
                            self.shim
                                .authenticate_cleartext(
                                    expected,
                                    username,
                                    character_set,
                                    initial_handshake,
                                    &candidate,
                                )
                                .await
                        }
                        None => false,
                    }
                }
            } else if let Some(sha256) = sha256 {
                let mut rsa_keys = None;
                let full_response = if response.as_slice() == [0x01] {
                    let keys = (sha256.rsa_keys)();
                    rsa_keys = Some(keys);
                    self.writer.write_all(keys.1.as_bytes())?;
                    self.writer.end_packet().await?;
                    self.writer.flush_all().await?;
                    let (encrypted_seq, encrypted) = self
                        .reader
                        .next_async_in_exchange(self.writer.sequence())
                        .await?
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "peer terminated sha256_password RSA authentication",
                            )
                        })?;
                    seq = encrypted_seq;
                    self.writer
                        .set_compressed_sequence(self.reader.compressed_sequence());
                    encrypted.to_vec()
                } else {
                    response
                };
                used_password |= auth_response_uses_password(&full_response);
                match decode_caching_sha2_full_auth(
                    || rsa_keys.unwrap_or_else(|| (sha256.rsa_keys)()).0,
                    salt,
                    &full_response,
                    self.secure_transport,
                ) {
                    Some(candidate) => {
                        self.shim
                            .authenticate_cleartext(
                                expected,
                                username,
                                character_set,
                                initial_handshake,
                                &candidate,
                            )
                            .await
                    }
                    None => false,
                }
            } else {
                self.shim
                    .authenticate(
                        expected,
                        username,
                        character_set,
                        initial_handshake,
                        salt,
                        &response,
                    )
                    .await
            };
        // The registered packet-reading test/cleartext handler sets YES once
        // its real reply reached it, even for an empty or wrong reply. An IO
        // failure above never reaches this frontier.
        if initial_data.is_some() {
            used_password = true;
        }
        if !authenticated {
            return Ok((false, seq, used_password));
        }
        // The same backend attempt carries the accepted prefix. Neither the
        // ordinal nor this capability bit creates credential authority.
        for _ in 0..2 {
            let Some((plugin, prompt)) = self.shim.next_authentication_factor().await? else {
                return Ok((true, seq, used_password));
            };
            if !self
                .client_capabilities
                .contains(CapabilityFlags::CLIENT_PLUGIN_AUTH)
                || !self
                    .client_capabilities
                    .contains(CapabilityFlags::MULTI_FACTOR_AUTHENTICATION)
                || plugin.is_empty()
            {
                return Ok((false, seq, used_password));
            }
            // The previous response has already been consumed by its handler;
            // only the new packet is borrowed by the next handler.
            self.writer.set_seq(seq.wrapping_add(1));
            self.writer.write_all(&[0x02])?;
            self.writer.write_all(plugin.as_bytes())?;
            self.writer.write_all(&[0x00])?;
            self.writer.write_all(prompt)?;
            self.writer.end_packet().await?;
            self.writer.flush_all().await?;
            let (response_seq, response) = self
                .reader
                .next_async_in_exchange(self.writer.sequence())
                .await?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "peer terminated next-factor authentication",
                    )
                })?;
            seq = response_seq;
            self.writer
                .set_compressed_sequence(self.reader.compressed_sequence());
            // Both currently installed external handlers issue PASSWORD_USED_YES.
            used_password = true;
            if !self
                .shim
                .authenticate(
                    plugin,
                    username,
                    character_set,
                    initial_handshake,
                    salt,
                    &response,
                )
                .await
            {
                return Ok((false, seq, used_password));
            }
        }
        Ok((true, seq, used_password))
    }

    async fn apply_authentication_result(
        &mut self,
        username: &[u8],
        character_set: u16,
        initial_handshake: bool,
        authenticated: bool,
    ) -> bool {
        let admitted = self
            .shim
            .on_authentication_result(username, character_set, initial_handshake, authenticated)
            .await;
        authenticated && admitted
    }

    async fn run(mut self) -> Result<(), B::Error> {
        let result = self.run_commands().await;
        let cleanup = self.shim.on_disconnect().await;
        match result {
            Err(error) => Err(error),
            Ok(()) => cleanup,
        }
    }

    async fn run_commands(&mut self) -> Result<(), B::Error> {
        use crate::commands::Command;

        let initialization_error = self.shim.initialize_connection().await;
        let mut stmts: HashMap<u32, _> = HashMap::new();
        loop {
            self.reader
                .set_max_allowed_packet(self.shim.max_allowed_packet());
            // An existing init-connect error owns its original first-command
            // response. Do not replace it with a new read-admission condition.
            let mut shutdown = self.shim.connection_shutdown();
            if initialization_error.is_none() {
                // A completed response has already been flushed. An existing
                // shutdown owns this boundary before another read admission
                // can report a second condition on the closed connection.
                let admission = tokio::select! {
                    biased;
                    _ = &mut shutdown => break,
                    admission = self.shim.before_command_read() => admission?,
                };
                if let Some((code, state, message)) = admission {
                    // Native net_new_transaction resets only pkt_nr before
                    // memory admission. No read has reset compress_pkt_nr yet;
                    // keep the writer's actual previous compressed sequence.
                    self.writer.set_seq(0);
                    writers::write_err_raw(code, &state, message.as_bytes(), &mut self.writer)
                        .await?;
                    self.writer.flush_all().await?;
                    break;
                }
            }
            let read = self.reader.next_async_new_command(self.shim.idle_timeout());
            let packet = tokio::select! {
                biased;
                _ = &mut shutdown => break,
                packet = read => packet.map_err(B::Error::from)?,
            };
            let Some((seq, packet)) = packet else {
                break;
            };
            self.writer.set_seq(seq.wrapping_add(1));
            self.writer
                .set_compressed_sequence(self.reader.compressed_sequence());
            if let Some((kind, message)) = &initialization_error {
                writers::write_err(*kind, message.as_bytes(), &mut self.writer).await?;
                self.writer.flush_all().await?;
                break;
            }
            let res = commands::parse(&packet);
            match res {
                Ok(cmd) => {
                    let mut command_started = false;
                    if !matches!(&cmd.1, Command::Query(_) | Command::Execute { .. }) {
                        self.shim.on_command_received(packet[0])?;
                        self.shim.on_command_begin(packet[0]).await?;
                        command_started = true;
                    }
                    if let Some((kind, message)) = if command_started {
                        self.shim.command_admission_error(packet[0]).await?
                    } else {
                        None
                    } {
                        writers::write_err(kind, message.as_bytes(), &mut self.writer).await?;
                        if command_started {
                            self.shim.on_command_finished(packet[0])?;
                        }
                        self.writer.flush_all().await?;
                        continue;
                    }
                    match cmd.1 {
                        Command::Query(q) => {
                            if q.len() > self.shim.max_allowed_packet() {
                                writers::write_err(
                                    ErrorKind::ER_NET_PACKET_TOO_LARGE,
                                    b"Got a packet bigger than 'max_allowed_packet' bytes",
                                    &mut self.writer,
                                )
                                .await?;
                                self.writer.flush_all().await?;
                                continue;
                            }
                            let named = self
                                .client_capabilities
                                .contains(CapabilityFlags::CLIENT_QUERY_ATTRIBUTES);
                            let admission = if named {
                                Some(self.shim.query_attributes_admission().ok_or_else(|| {
                                    io::Error::new(
                                        io::ErrorKind::Unsupported,
                                        "query-attributes allocation issuer is not installed",
                                    )
                                })?)
                            } else {
                                None
                            };
                            let mut bindings = match ParamParser::query(q, named, admission)
                                .parse_bindings()
                            {
                                Ok(bindings) => bindings,
                                Err(error) => {
                                    if let Some(kind) = error.error_kind() {
                                        writers::write_err(kind, error.message(), &mut self.writer)
                                            .await?;
                                        self.writer.flush_all().await?;
                                        continue;
                                    }
                                    return Err(error.into_io().into());
                                }
                            };
                            if named {
                                bindings.retain_packet(
                                    packet.owned_range(packet.len() - q.len()..packet.len())?,
                                );
                            }
                            self.shim.on_command_received(packet[0])?;
                            self.shim.on_command_begin(packet[0]).await?;
                            command_started = true;
                            if let Some((kind, message)) =
                                self.shim.command_admission_error(packet[0]).await?
                            {
                                writers::write_err(kind, message.as_bytes(), &mut self.writer)
                                    .await?;
                                self.shim.on_command_finished(packet[0])?;
                                self.writer.flush_all().await?;
                                continue;
                            }
                            let q = bindings.suffix();
                            let results = QueryResultWriter::new(
                                &mut self.writer,
                                false,
                                self.client_capabilities,
                            );
                            let preflight = self.shim.preflight_local_infile_with_bindings(
                                &bindings,
                                self.client_capabilities
                                    .contains(CapabilityFlags::CLIENT_LOCAL_FILES),
                                results,
                            );
                            let admission = match poll_command_response(
                                &mut self.reader,
                                preflight,
                                "peer terminated connection while query was running",
                            )
                            .await
                            {
                                CommandResponseOutcome::Completed(result) => result?,
                                CommandResponseOutcome::Peer(error) => {
                                    self.shim.on_query_cancelled().await?;
                                    return Err(error.into());
                                }
                            };
                            match admission {
                                LocalInfilePreflight::Request { filename, results } => {
                                    results.writer.write_all(&[0xfb])?;
                                    results.writer.write_all(&filename)?;
                                    results.writer.end_packet().await?;
                                    results.writer.flush_all().await?;
                                    // The request and upload share one NET exchange. Use
                                    // the counters actually emitted by this same writer,
                                    // including a fragmented filename/compressed flush.
                                    let mut expected_local_infile_seq = results.writer.sequence();
                                    self.reader.set_compressed_sequence(
                                        results.writer.compressed_sequence(),
                                    );
                                    let max_allowed_packet = self.shim.max_allowed_packet();
                                    let mut received = 0usize;
                                    let mut exceeds_limit = false;
                                    let mut last_local_infile_seq;
                                    // An oversized LOCAL INFILE transfer is recoverable only after
                                    // consuming its terminating empty packet. Individual protocol
                                    // frames remain bounded by MySQL's 24-bit packet format while
                                    // the aggregate uses max_allowed_packet below.
                                    self.reader
                                        .set_max_allowed_packet(max_allowed_packet.max(U24_MAX));
                                    loop {
                                        let next_packet = self
                                            .reader
                                            .next_async_in_exchange(expected_local_infile_seq)
                                            .await;
                                        let (packet_seq, packet) = match next_packet {
                                            Ok(Some(packet)) => packet,
                                            Ok(None) => {
                                                self.reader
                                                    .set_max_allowed_packet(max_allowed_packet);
                                                self.shim.on_local_infile_abort().await?;
                                                return Err(io::Error::new(
                                                io::ErrorKind::ConnectionAborted,
                                                "peer terminated connection during LOCAL INFILE",
                                            )
                                            .into());
                                            }
                                            Err(error) => {
                                                self.reader
                                                    .set_max_allowed_packet(max_allowed_packet);
                                                self.shim.on_local_infile_abort().await?;
                                                return Err(error.into());
                                            }
                                        };
                                        last_local_infile_seq = packet_seq;
                                        expected_local_infile_seq = packet_seq.wrapping_add(1);
                                        if packet.is_empty() {
                                            break;
                                        }
                                        match received.checked_add(packet.len()) {
                                            Some(total) => {
                                                received = total;
                                                exceeds_limit |= received > max_allowed_packet;
                                            }
                                            None => exceeds_limit = true,
                                        }
                                        if !exceeds_limit {
                                            if let Err(error) =
                                                self.shim.on_local_infile_data(&packet).await
                                            {
                                                self.reader
                                                    .set_max_allowed_packet(max_allowed_packet);
                                                self.shim.on_local_infile_abort().await?;
                                                return Err(error);
                                            }
                                        }
                                    }
                                    self.reader.set_max_allowed_packet(max_allowed_packet);
                                    results
                                        .writer
                                        .set_seq(last_local_infile_seq.wrapping_add(1));
                                    results
                                        .writer
                                        .set_compressed_sequence(self.reader.compressed_sequence());
                                    if exceeds_limit {
                                        self.shim.on_local_infile_abort().await?;
                                        results
                                            .error(
                                                ErrorKind::ER_NET_PACKET_TOO_LARGE,
                                                b"LOAD DATA LOCAL exceeds max_allowed_packet",
                                            )
                                            .await?;
                                    } else {
                                        let finish = self.shim.on_local_infile_end(results);
                                        match poll_command_response(
                                            &mut self.reader,
                                            finish,
                                            "peer terminated connection while query was running",
                                        )
                                        .await
                                        {
                                            CommandResponseOutcome::Completed(result) => result?,
                                            CommandResponseOutcome::Peer(error) => {
                                                self.shim.on_query_cancelled().await?;
                                                return Err(error.into());
                                            }
                                        }
                                    }
                                    self.shim.on_query_finished().await?;
                                    command_started = false;
                                }
                                LocalInfilePreflight::Completed => {
                                    self.shim.on_query_finished().await?;
                                    command_started = false;
                                }
                                LocalInfilePreflight::Continue(results)
                                    if !self.process_use_statement_on_query
                                        && !named
                                        && (q.starts_with(b"USE ") || q.starts_with(b"use ")) =>
                                {
                                    drop(results);
                                    let w = InitWriter {
                                        client_capabilities: self.client_capabilities,
                                        writer: &mut self.writer,
                                    };
                                    let schema = ::std::str::from_utf8(&q[b"USE ".len()..])
                                        .map_err(|e| {
                                            io::Error::new(io::ErrorKind::InvalidData, e)
                                        })?;
                                    let schema =
                                        schema.trim().trim_end_matches(';').trim_matches('`');
                                    self.shim.on_init(schema.as_bytes(), w).await?;
                                }
                                LocalInfilePreflight::Continue(results) => {
                                    let query = async {
                                        if named {
                                            self.shim.on_query_bindings(bindings, results).await
                                        } else {
                                            self.shim.on_query(q, results).await
                                        }
                                    };
                                    let outcome = poll_command_response(
                                        &mut self.reader,
                                        query,
                                        "peer terminated connection while query was running",
                                    )
                                    .await;
                                    match outcome {
                                        CommandResponseOutcome::Completed(result) => {
                                            self.shim.on_query_finished().await?;
                                            command_started = false;
                                            result?;
                                        }
                                        CommandResponseOutcome::Peer(error) => {
                                            self.shim.on_query_cancelled().await?;
                                            return Err(error.into());
                                        }
                                    }
                                }
                            }
                        }
                        Command::Prepare(q) => {
                            let w = StatementMetaWriter {
                                writer: &mut self.writer,
                                stmts: &mut stmts,
                                client_capabilities: self.client_capabilities,
                            };

                            self.shim.on_prepare(q, w).await?;
                        }
                        Command::CreateDatabase(_) | Command::DropDatabase(_) => {
                            // COM_CREATE_DB/COM_DROP_DB were removed from the
                            // modern server command API. MySQL 8 parses their
                            // command bytes but answers 1047 rather than
                            // translating them into SQL DDL.
                            writers::write_err(
                                ErrorKind::ER_UNKNOWN_COM_ERROR,
                                b"Unknown command",
                                &mut self.writer,
                            )
                            .await?;
                        }
                        Command::Refresh(flags) => {
                            if let Some(query) = mysql_refresh_query(flags) {
                                self.run_query_until_disconnect(
                                    format!("{query} /* COM_REFRESH */").as_bytes(),
                                    false,
                                )
                                .await?;
                                command_started = false;
                            } else {
                                writers::write_err(
                                    ErrorKind::ER_WRONG_ARGUMENTS,
                                    b"invalid COM_REFRESH flags",
                                    &mut self.writer,
                                )
                                .await?;
                            }
                        }
                        Command::Statistics => {
                            if let Some((kind, message)) =
                                self.shim.statistics_command_error().await
                            {
                                writers::write_err(kind, message.as_bytes(), &mut self.writer)
                                    .await?;
                            } else {
                                self.shim
                                    .on_statistics(StatisticsWriter {
                                        writer: &mut self.writer,
                                    })
                                    .await?;
                            }
                        }
                        Command::ProcessInfo => {
                            let outcome = {
                                let results = QueryResultWriter::new(
                                    &mut self.writer,
                                    false,
                                    self.client_capabilities,
                                );
                                poll_command_response(
                                    &mut self.reader,
                                    self.shim.on_process_info(results),
                                    "peer terminated connection while process information was running",
                                ).await
                            };
                            match outcome {
                                CommandResponseOutcome::Completed(result) => result?,
                                CommandResponseOutcome::Peer(error) => {
                                    self.shim.on_query_cancelled().await?;
                                    return Err(error.into());
                                }
                            }
                        }
                        Command::ProcessKill(connection_id) => {
                            self.run_query_until_disconnect(
                                format!("KILL CONNECTION {connection_id}").as_bytes(),
                                false,
                            )
                            .await?;
                            command_started = false;
                        }
                        Command::SetOption(option) => {
                            match option {
                                0 => self
                                    .client_capabilities
                                    .insert(CapabilityFlags::CLIENT_MULTI_STATEMENTS),
                                1 => self
                                    .client_capabilities
                                    .remove(CapabilityFlags::CLIENT_MULTI_STATEMENTS),
                                _ => {
                                    writers::write_err(
                                        ErrorKind::ER_UNKNOWN_COM_ERROR,
                                        b"Unknown command",
                                        &mut self.writer,
                                    )
                                    .await?;
                                    self.shim.on_command_finished(packet[0])?;
                                    self.writer.flush_all().await?;
                                    continue;
                                }
                            }
                            self.shim
                                .on_client_capabilities_changed(self.client_capabilities);
                            let status = self.shim.status_flags();
                            if self
                                .client_capabilities
                                .contains(CapabilityFlags::CLIENT_DEPRECATE_EOF)
                            {
                                writers::write_ok_packet(
                                    &mut self.writer,
                                    self.client_capabilities,
                                    OkResponse {
                                        header: 0xfe,
                                        status_flags: status,
                                        ..OkResponse::default()
                                    },
                                )
                                .await?;
                            } else {
                                writers::write_eof_packet(&mut self.writer, status, 0).await?;
                            }
                        }
                        Command::Shutdown => {
                            writers::write_err(
                                ErrorKind::ER_SPECIFIC_ACCESS_DENIED_ERROR,
                                b"Access denied; administrative privilege required",
                                &mut self.writer,
                            )
                            .await?;
                        }
                        Command::Debug => {
                            // The backend's command gate has already checked
                            // the actual session. Native COM_DEBUG uses my_eof;
                            // it does not expose an internal dump over the wire.
                            let status = self.shim.status_flags();
                            if self
                                .client_capabilities
                                .contains(CapabilityFlags::CLIENT_DEPRECATE_EOF)
                            {
                                writers::write_ok_packet(
                                    &mut self.writer,
                                    self.client_capabilities,
                                    OkResponse {
                                        header: 0xfe,
                                        status_flags: status,
                                        ..OkResponse::default()
                                    },
                                )
                                .await?;
                            } else {
                                writers::write_eof_packet(&mut self.writer, status, 0).await?;
                            }
                        }
                        Command::TableDump(_) => {
                            writers::write_err(
                                ErrorKind::ER_NOT_SUPPORTED_YET,
                                b"COM_TABLE_DUMP is not supported",
                                &mut self.writer,
                            )
                            .await?;
                        }
                        Command::Execute {
                            stmt,
                            flags,
                            params,
                        } => {
                            let Some(state) = stmts.get_mut(&stmt) else {
                                self.shim.on_command_received(packet[0])?;
                                self.shim.on_command_begin(packet[0]).await?;
                                if let Some((kind, message)) =
                                    self.shim.command_admission_error(packet[0]).await?
                                {
                                    writers::write_err(kind, message.as_bytes(), &mut self.writer)
                                        .await?;
                                    self.shim.on_command_finished(packet[0])?;
                                    self.writer.flush_all().await?;
                                    continue;
                                }
                                let message = format!(
                                    "Unknown prepared statement handler ({stmt}) given to mysql_stmt_precheck"
                                );
                                writers::write_err(
                                    ErrorKind::ER_UNKNOWN_STMT_HANDLER,
                                    message.as_bytes(),
                                    &mut self.writer,
                                )
                                .await?;
                                self.shim.on_command_finished(packet[0])?;
                                self.writer.flush_all().await?;
                                continue;
                            };
                            // Same actual allocation, not a copied tail or a
                            // borrow of a mutable reader buffer. Lookup first.
                            let params =
                                packet.owned_range(packet.len() - params.len()..packet.len())?;
                            let named = self
                                .client_capabilities
                                .contains(CapabilityFlags::CLIENT_QUERY_ATTRIBUTES);
                            let admission = if named {
                                Some(self.shim.query_attributes_admission().ok_or_else(|| {
                                    io::Error::new(
                                        io::ErrorKind::Unsupported,
                                        "query-attributes allocation issuer is not installed",
                                    )
                                })?)
                            } else {
                                None
                            };
                            self.run_execute_until_disconnect(
                                stmt,
                                &params,
                                state,
                                flags,
                                admission,
                                &mut command_started,
                            )
                            .await?;
                        }
                        Command::SendLongData { stmt, param, data } => {
                            let Some(state) = stmts.get_mut(&stmt) else {
                                // SEND_LONG_DATA never acknowledges even an
                                // unknown handler. A stray ERR would become the
                                // next real command's response.
                                self.shim.on_command_finished(packet[0])?;
                                continue;
                            };
                            if param >= state.params {
                                state.long_data_error = Some(ErrorKind::ER_WRONG_ARGUMENTS);
                                self.shim.on_command_finished(packet[0])?;
                                continue;
                            }
                            let current = state.long_data.get(&param).map_or(0, Vec::len);
                            let total = current.checked_add(data.len()).ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "COM_STMT_SEND_LONG_DATA size overflow",
                                )
                            })?;
                            if total > self.shim.max_allowed_packet() {
                                // COM_STMT_SEND_LONG_DATA has no response packet.
                                // MySQL defers an aggregate long-data failure to
                                // COM_STMT_EXECUTE as ER_UNKNOWN_ERROR, retaining
                                // the value from before this rejected append.
                                state.long_data_error = Some(ErrorKind::ER_UNKNOWN_ERROR);
                                self.shim.on_command_finished(packet[0])?;
                                continue;
                            }
                            state
                                .long_data
                                .entry(param)
                                .or_insert_with(Vec::new)
                                .extend(data);
                        }
                        Command::Close(stmt) => {
                            self.shim.on_close(stmt).await;
                            stmts.remove(&stmt);
                            // NOTE: spec dictates no response from server
                        }
                        Command::ResetStatement(stmt) => {
                            if let Some(state) = stmts.get_mut(&stmt) {
                                state.long_data.clear();
                                state.long_data_error = None;
                                self.shim.on_reset_statement(stmt).await?;
                                writers::write_ok_packet(
                                    &mut self.writer,
                                    self.client_capabilities,
                                    OkResponse {
                                        status_flags: self.shim.status_flags(),
                                        ..OkResponse::default()
                                    },
                                )
                                .await?;
                            } else {
                                writers::write_err(
                                    ErrorKind::ER_UNKNOWN_STMT_HANDLER,
                                    b"unknown prepared statement",
                                    &mut self.writer,
                                )
                                .await?;
                            }
                        }
                        Command::Fetch { stmt, rows } => {
                            let writer = QueryResultWriter::new(
                                &mut self.writer,
                                true,
                                self.client_capabilities,
                            );
                            self.shim.on_fetch(stmt, rows, writer).await?;
                        }
                        Command::ResetConnection => {
                            stmts.clear();
                            self.shim.on_reset_connection().await?;
                            writers::write_ok_packet(
                                &mut self.writer,
                                self.client_capabilities,
                                OkResponse {
                                    status_flags: self.shim.status_flags(),
                                    ..OkResponse::default()
                                },
                            )
                            .await?;
                        }
                        Command::ChangeUser(payload) => {
                            stmts.clear();
                            if let Some((code, state, message)) =
                                self.shim.on_change_user_begin().await?
                            {
                                writers::write_err_raw(
                                    code,
                                    &state,
                                    message.as_bytes(),
                                    &mut self.writer,
                                )
                                .await?;
                                self.shim.on_command_finished(packet[0])?;
                                self.writer.flush_all().await?;
                                break;
                            }
                            let request =
                                match parse_change_user_native(payload, self.client_capabilities) {
                                    Ok(request) => request,
                                    Err((_error, first_error)) => {
                                        let (kind, message) = match first_error {
                                            Some(kind) => (kind, "Unknown command".to_owned()),
                                            None => (
                                                ErrorKind::ER_ACCESS_DENIED_CHANGE_USER_ERROR,
                                                self.shim.authentication_error_message(
                                                    &[],
                                                    0,
                                                    false,
                                                    &[],
                                                ),
                                            ),
                                        };
                                        self.shim.on_change_user_error(
                                            kind as u16,
                                            *kind.sqlstate(),
                                            &message,
                                        );
                                        let (code, state, message) = self
                                            .shim
                                            .authentication_error_response()
                                            .unwrap_or((kind as u16, *kind.sqlstate(), message));
                                        writers::write_err_raw(
                                            code,
                                            &state,
                                            message.as_bytes(),
                                            &mut self.writer,
                                        )
                                        .await?;
                                        self.shim.on_command_finished(packet[0])?;
                                        self.writer.flush_all().await?;
                                        break;
                                    }
                                };
                            // Validate the packet's charset with the same backend initializer
                            // policy as initial authentication, before selecting a plugin.
                            // The live connection's visible charset is not changed here.
                            let client_collation = myc::collations::Collation::resolve(
                                myc::collations::CollationId::from(request.character_set),
                            );
                            if let Some((kind, message)) = self.shim.client_collation_error(
                                request.character_set,
                                client_collation.charset,
                                client_collation.collation,
                            ) {
                                self.shim.on_change_user_error(
                                    kind as u16,
                                    *kind.sqlstate(),
                                    &message,
                                );
                                let (code, state, message) = self
                                    .shim
                                    .authentication_error_response()
                                    .unwrap_or((kind as u16, *kind.sqlstate(), message));
                                writers::write_err_raw(
                                    code,
                                    &state,
                                    message.as_bytes(),
                                    &mut self.writer,
                                )
                                .await?;
                                self.shim.on_command_finished(packet[0])?;
                                self.writer.flush_all().await?;
                                break;
                            }
                            let salt = self.shim.salt();
                            let exchange = self
                                .authenticate_exchange(
                                    request.username,
                                    request.character_set,
                                    false,
                                    request.plugin,
                                    &salt,
                                    (seq, request.auth_data),
                                )
                                .await;
                            let (authenticated, auth_seq, used_password) = match exchange {
                                Ok(result) => result,
                                Err(error) => {
                                    self.apply_authentication_result(
                                        request.username,
                                        request.character_set,
                                        false,
                                        false,
                                    )
                                    .await;
                                    return Err(error);
                                }
                            };
                            let authenticated = self
                                .apply_authentication_result(
                                    request.username,
                                    request.character_set,
                                    false,
                                    authenticated,
                                )
                                .await;
                            self.writer.set_seq(auth_seq.wrapping_add(1));
                            if !authenticated {
                                let password_marker =
                                    if used_password { &[1][..] } else { &[][..] };
                                let message = self.shim.authentication_error_message(
                                    request.username,
                                    request.character_set,
                                    false,
                                    password_marker,
                                );
                                if let Some((code, state, first_message)) =
                                    self.shim.authentication_error_response()
                                {
                                    writers::write_err_raw(
                                        code,
                                        &state,
                                        first_message.as_bytes(),
                                        &mut self.writer,
                                    )
                                    .await?;
                                } else {
                                    let kind = ErrorKind::ER_ACCESS_DENIED_CHANGE_USER_ERROR;
                                    self.shim.on_change_user_error(
                                        kind as u16,
                                        *kind.sqlstate(),
                                        &message,
                                    );
                                    let (code, state, message) = self
                                        .shim
                                        .authentication_error_response()
                                        .unwrap_or((kind as u16, *kind.sqlstate(), message));
                                    writers::write_err_raw(
                                        code,
                                        &state,
                                        message.as_bytes(),
                                        &mut self.writer,
                                    )
                                    .await?;
                                }
                                self.shim.on_command_finished(packet[0])?;
                                self.writer.flush_all().await?;
                                break;
                            }
                            if let Some((kind, message)) = self
                                .shim
                                .on_change_user(
                                    request.username,
                                    request.database,
                                    request.character_set,
                                )
                                .await?
                            {
                                // The real install producer may already have published
                                // first DA. Only a backend without it receives this
                                // original transport failure publication.
                                let first = self.shim.authentication_error_response();
                                if first.is_none() {
                                    self.shim.on_change_user_error(
                                        kind as u16,
                                        *kind.sqlstate(),
                                        &message,
                                    );
                                }
                                let (code, state, message) = first
                                    .or_else(|| self.shim.authentication_error_response())
                                    .unwrap_or((kind as u16, *kind.sqlstate(), message));
                                writers::write_err_raw(
                                    code,
                                    &state,
                                    message.as_bytes(),
                                    &mut self.writer,
                                )
                                .await?;
                                self.shim.on_command_finished(packet[0])?;
                                self.writer.flush_all().await?;
                                break;
                            } else {
                                self.shim
                                    .on_change_user_connection_attrs(request.connection_attrs)?;
                                writers::write_ok_packet(
                                    &mut self.writer,
                                    self.client_capabilities,
                                    OkResponse {
                                        status_flags: self.shim.status_flags(),
                                        ..OkResponse::default()
                                    },
                                )
                                .await?;
                            }
                        }
                        Command::ListFields(payload) => {
                            let w = QueryResultWriter::new(
                                &mut self.writer,
                                false,
                                self.client_capabilities,
                            );
                            self.shim.on_list_fields(payload, w).await?;
                        }
                        Command::Init(schema) => {
                            let w = InitWriter {
                                client_capabilities: self.client_capabilities,
                                writer: &mut self.writer,
                            };
                            self.shim.on_init(schema, w).await?;
                        }
                        Command::Ping => {
                            writers::write_ok_packet(
                                &mut self.writer,
                                self.client_capabilities,
                                OkResponse {
                                    status_flags: self.shim.status_flags(),
                                    ..OkResponse::default()
                                },
                            )
                            .await?;
                        }
                        Command::Unknown(command) => {
                            writers::write_err(
                                ErrorKind::ER_UNKNOWN_COM_ERROR,
                                format!("unknown command {command}").as_bytes(),
                                &mut self.writer,
                            )
                            .await?;
                        }
                        Command::Quit => {
                            self.shim.on_command_finished(packet[0])?;
                            break;
                        }
                    }
                    if command_started {
                        self.shim.on_command_finished(packet[0])?;
                    }
                    self.writer.flush_all().await?;
                }
                Err(_) => {
                    // Native get_command treats an empty packet as COM_SLEEP,
                    // which dispatches and rejects it, unlike malformed fields.
                    if packet.is_empty() {
                        self.shim.on_command_received(0)?;
                        self.shim.on_command_begin(0).await?;
                        if let Some((kind, message)) = self.shim.command_admission_error(0).await? {
                            writers::write_err(kind, message.as_bytes(), &mut self.writer).await?;
                            self.shim.on_command_finished(0)?;
                            self.writer.flush_all().await?;
                            continue;
                        }
                    }
                    let bind_command = matches!(packet.first(), Some(0x03 | 0x17));
                    writers::write_err(
                        if bind_command {
                            ErrorKind::ER_MALFORMED_PACKET
                        } else {
                            ErrorKind::ER_UNKNOWN_COM_ERROR
                        },
                        if bind_command {
                            &b"Malformed communication packet."[..]
                        } else {
                            &b"malformed command packet"[..]
                        },
                        &mut self.writer,
                    )
                    .await?;
                    if packet.is_empty() {
                        self.shim.on_command_finished(0)?;
                    }
                    self.writer.flush_all().await?;
                }
            }
        }
        Ok(())
    }

    async fn run_query_until_disconnect(
        &mut self,
        query: &[u8],
        binary: bool,
    ) -> Result<(), B::Error> {
        let outcome = {
            let writer = QueryResultWriter::new(&mut self.writer, binary, self.client_capabilities);
            let query = self.shim.on_query(query, writer);
            poll_command_response(
                &mut self.reader,
                query,
                "peer terminated connection while query was running",
            )
            .await
        };
        match outcome {
            CommandResponseOutcome::Completed(result) => {
                self.shim.on_query_finished().await?;
                result
            }
            CommandResponseOutcome::Peer(error) => {
                self.shim.on_query_cancelled().await?;
                Err(error.into())
            }
        }
    }

    async fn run_execute_until_disconnect(
        &mut self,
        stmt: u32,
        raw_params: &bytes::Bytes,
        state: &mut StatementData,
        flags: u8,
        admission: Option<CommandAllocationAdmission>,
        command_started: &mut bool,
    ) -> Result<(), B::Error> {
        let named = self
            .client_capabilities
            .contains(CapabilityFlags::CLIENT_QUERY_ATTRIBUTES);
        // Native STMT_ERROR is sticky until RESET/CLOSE. Packet framing and
        // the actual parameter setter still precede that execution gate.
        let deferred_error = state.long_data_error;
        let mut bindings = match ParamParser::execute(raw_params, state, named, flags, admission)
            .parse_bindings()
        {
            Ok(bindings) => bindings,
            Err(error) => {
                if error.phase == crate::params::BindErrorPhase::StatementCount {
                    // The original decoder validated the whole native frame;
                    // N<P is dispatch's precheck, not malformed get_command.
                    self.shim.on_command_received(0x17)?;
                    self.shim.on_command_begin(0x17).await?;
                    *command_started = true;
                    if let Some((kind, message)) = self.shim.command_admission_error(0x17).await? {
                        writers::write_err(kind, message.as_bytes(), &mut self.writer).await?;
                        self.writer.flush_all().await?;
                        return Ok(());
                    }
                }
                if let Some(kind) = error.error_kind() {
                    writers::write_err(kind, error.message(), &mut self.writer).await?;
                    self.writer.flush_all().await?;
                    return Ok(());
                }
                return Err(error.into_io().into());
            }
        };
        if named {
            bindings.retain_packet(raw_params.clone());
        }
        self.shim.on_command_received(0x17)?;
        self.shim.on_command_begin(0x17).await?;
        *command_started = true;
        if let Some((kind, message)) = self.shim.command_admission_error(0x17).await? {
            writers::write_err(kind, message.as_bytes(), &mut self.writer).await?;
            self.writer.flush_all().await?;
            return Ok(());
        }
        if let Some(kind) = deferred_error {
            let parameter_error = match bindings.bind_placeholders() {
                Ok(parameters) => {
                    drop(parameters);
                    None
                }
                Err(error) => Some(error),
            };
            drop(bindings);
            if let Some(error) = parameter_error {
                // set_parameters resets actual values on setter failure,
                // without clearing the statement's deferred STMT_ERROR.
                state.long_data.clear();
                if let Some(kind) = error.error_kind() {
                    writers::write_err(kind, error.message(), &mut self.writer).await?;
                    self.writer.flush_all().await?;
                    return Ok(());
                }
                return Err(error.into_io().into());
            }
            let message: &[u8] = match kind {
                ErrorKind::ER_WRONG_ARGUMENTS => {
                    b"Incorrect arguments to mysql_stmt_precheck"
                }
                ErrorKind::ER_UNKNOWN_ERROR => {
                    b"Parameter of prepared statement which is set through mysql_send_long_data() is longer than 'max_allowed_packet' bytes"
                }
                _ => unreachable!("only native long-data causes enter deferred statement state"),
            };
            writers::write_err(kind, message, &mut self.writer).await?;
            self.writer.flush_all().await?;
            return Ok(());
        }
        if !named && flags & myc::constants::CursorType::CURSOR_TYPE_READ_ONLY.bits() != 0 {
            let outcome = {
                let writer =
                    QueryResultWriter::new(&mut self.writer, true, self.client_capabilities);
                let execute =
                    self.shim
                        .on_execute_cursor(stmt, ParamParser::decoded(bindings), writer);
                poll_command_response(
                    &mut self.reader,
                    execute,
                    "peer terminated connection while prepared query was running",
                )
                .await
            };
            // Only this real setter/execution path reaches native parameter
            // reset. Framing and early STMT_ERROR above retain their values.
            state.long_data.clear();
            return match outcome {
                CommandResponseOutcome::Completed(result) => result,
                CommandResponseOutcome::Peer(error) => {
                    self.shim.on_query_cancelled().await?;
                    Err(error.into())
                }
            };
        }

        let outcome = {
            let writer = QueryResultWriter::new(&mut self.writer, true, self.client_capabilities);
            let execute = async {
                if named {
                    self.shim.on_execute_bindings(stmt, bindings, writer).await
                } else {
                    self.shim
                        .on_execute(stmt, ParamParser::decoded(bindings), writer)
                        .await
                }
            };
            poll_command_response(
                &mut self.reader,
                execute,
                "peer terminated connection while prepared query was running",
            )
            .await
        };
        state.long_data.clear();
        match outcome {
            CommandResponseOutcome::Completed(result) => {
                self.shim.on_query_finished().await?;
                *command_started = false;
                result
            }
            CommandResponseOutcome::Peer(error) => {
                self.shim.on_query_cancelled().await?;
                Err(error.into())
            }
        }
    }
}

fn auth_response_uses_password(response: &[u8]) -> bool {
    !response.is_empty() && response != [0]
}

fn decode_caching_sha2_full_auth<'key>(
    private_key_pem: impl FnOnce() -> &'key str,
    salt: &[u8],
    response: &[u8],
    secure_transport: bool,
) -> Option<Vec<u8>> {
    if secure_transport && response.last() == Some(&0) {
        return Some(response[..response.len() - 1].to_vec());
    }
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    // TLS cleartext does not borrow or initialize RSA state. Every other
    // path retains its original RSA decoding and rejection behavior.
    let private_key_pem = private_key_pem();
    let Ok(private_key) = rsa::RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(private_key_pem))
    else {
        return None;
    };
    let Ok(mut clear) = private_key.decrypt(rsa::Oaep::new::<sha1::Sha1>(), response) else {
        return None;
    };
    if salt.is_empty() {
        return None;
    }
    for (index, byte) in clear.iter_mut().enumerate() {
        *byte ^= salt[index % salt.len()];
    }
    (clear.last() == Some(&0)).then(|| {
        clear.pop();
        clear
    })
}
