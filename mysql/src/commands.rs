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

use crate::myc::constants::{CapabilityFlags, Command as CommandByte};

type ConnectionAttributes = Vec<u8>;

#[derive(Debug)]
pub struct ClientHandshake {
    #[allow(dead_code)]
    pub(crate) maxps: u32,
    pub(crate) capabilities: CapabilityFlags,
    #[allow(dead_code)]
    pub(crate) collation: u16,
    #[allow(dead_code)]
    pub(crate) db: Option<Vec<u8>>,
    pub(crate) username: Option<Vec<u8>>,
    pub(crate) auth_response: Vec<u8>,
    pub(crate) auth_plugin: Vec<u8>,
    pub(crate) connection_attrs: ConnectionAttributes,
    pub(crate) zstd_compression_level: Option<u8>,
}

#[allow(clippy::branches_sharing_code)]
pub fn client_handshake(
    i: &[u8],
    after_tls: bool,
    server_capabilities: CapabilityFlags,
) -> nom::IResult<&[u8], ClientHandshake> {
    // mysql handshake protocol documentation
    // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_response.html
    let (i, cap) = nom::number::complete::le_u16(i)?;

    let mut capabilities = CapabilityFlags::from_bits_truncate(cap as u32);
    if capabilities.contains(CapabilityFlags::CLIENT_PROTOCOL_41) {
        // HandshakeResponse41
        let (i, cap2) = nom::number::complete::le_u16(i)?;
        let cap = ((cap2 as u32) << 16) | (cap as u32);

        capabilities = CapabilityFlags::from_bits_truncate(cap);

        let (i, maxps) = nom::number::complete::le_u32(i)?;
        let (i, collation) = nom::bytes::complete::take(1u8)(i)?;

        let (i, _) = nom::bytes::complete::take(23u8)(i)?;

        if !after_tls && capabilities.contains(CapabilityFlags::CLIENT_SSL) {
            return Ok((
                i,
                ClientHandshake {
                    capabilities,
                    maxps,
                    collation: u16::from(collation[0]),
                    username: None,
                    db: None,
                    auth_response: vec![],
                    auth_plugin: vec![],
                    connection_attrs: Vec::new(),
                    zstd_compression_level: None,
                },
            ));
        }

        let (i, username) = if after_tls || !capabilities.contains(CapabilityFlags::CLIENT_SSL) {
            let (i, user) = nom::bytes::complete::take_until(&b"\0"[..])(i)?;
            let (i, _) = nom::bytes::complete::tag(b"\0")(i)?;
            (i, Some(user.to_owned()))
        } else {
            (i, None)
        };

        let (i, auth_response) =
            if capabilities.contains(CapabilityFlags::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
                let (i, size) = read_length_encoded_number(i)?;
                nom::bytes::complete::take(size)(i)?
            } else {
                // MySQL 8.0 HandshakeResponse41 always uses the one-byte
                // auth length without LENENC_CLIENT_DATA. The old secure
                // connection bit does not select a NUL-terminated encoding.
                let (i, size) = nom::number::complete::le_u8(i)?;
                nom::bytes::complete::take(size)(i)?
            };

        let (i, db) = if capabilities.contains(CapabilityFlags::CLIENT_CONNECT_WITH_DB) {
            let (i, db) = nom::bytes::complete::take_until(&b"\0"[..])(i)?;
            let (i, _) = nom::bytes::complete::tag(b"\0")(i)?;
            (i, Some(db))
        } else {
            (i, None)
        };

        let (i, auth_plugin) =
            if capabilities.contains(CapabilityFlags::CLIENT_PLUGIN_AUTH) && !i.is_empty() {
                let (i, auth_plugin) = nom::bytes::complete::take_until(&b"\0"[..])(i)?;

                let (i, _) = nom::bytes::complete::tag(b"\0")(i)?;
                (i, auth_plugin)
            } else {
                (i, &b""[..])
            };

        // libmysqlclient may keep CONNECT_ATTRS in its flags even when the
        // server does not advertise it. Its send_client_connect_attrs writes
        // the field only when the server supports it; do not invent that field.
        let (i, connection_attrs) = if (capabilities & server_capabilities)
            .contains(CapabilityFlags::CLIENT_CONNECT_ATTRS)
        {
            parse_connection_attrs(i)?
        } else {
            (i, Vec::new())
        };

        let (i, zstd_compression_level) = if capabilities
            .contains(CapabilityFlags::CLIENT_ZSTD_COMPRESSION_ALGORITHM)
            && !i.is_empty()
        {
            let (i, level) = nom::number::complete::le_u8(i)?;
            (i, Some(level))
        } else {
            (i, None)
        };

        Ok((
            i,
            ClientHandshake {
                capabilities,
                maxps,
                collation: u16::from(collation[0]),
                username,
                db: db.map(|c| c.to_vec()),
                auth_response: auth_response.to_vec(),
                auth_plugin: auth_plugin.to_vec(),
                connection_attrs,
                zstd_compression_level,
            },
        ))
    } else {
        // HandshakeResponse320
        let (i, maxps1) = nom::number::complete::le_u16(i)?;
        let (i, maxps2) = nom::number::complete::le_u8(i)?;
        let maxps = ((maxps2 as u32) << 16) | (maxps1 as u32);
        let (i, username) = nom::bytes::complete::take_until(&b"\0"[..])(i)?;
        let (i, _) = nom::bytes::complete::tag(b"\0")(i)?;

        let (i, auth_response, db) =
            if capabilities.contains(CapabilityFlags::CLIENT_CONNECT_WITH_DB) {
                let (i, auth_response) = nom::bytes::complete::tag(b"\0")(i)?;
                let (i, _) = nom::bytes::complete::tag(b"\0")(i)?;

                let (i, db) = nom::bytes::complete::tag(b"\0")(i)?;
                let (i, _) = nom::bytes::complete::tag(b"\0")(i)?;

                (i, auth_response, Some(db))
            } else {
                (&b""[..], i, None)
            };

        Ok((
            i,
            ClientHandshake {
                capabilities,
                maxps,
                collation: 0,
                username: Some(username.to_vec()),
                db: db.map(|c| c.to_vec()),
                auth_response: auth_response.to_vec(),
                auth_plugin: vec![],
                connection_attrs: Vec::new(),
                zstd_compression_level: None,
            },
        ))
    }
}

fn parse_connection_attrs(i: &[u8]) -> nom::IResult<&[u8], ConnectionAttributes> {
    if i.first() == Some(&0xfb) {
        return Err(nom::Err::Failure(nom::error::Error::new(
            i,
            nom::error::ErrorKind::TooLarge,
        )));
    }
    // Native net_field_length_ll's nine-byte branch also consumes 0xff.
    let (i, size) = if i.first() == Some(&0xff) {
        let (remaining, bytes) = nom::bytes::complete::take(8usize)(&i[1..])?;
        (
            remaining,
            u64::from_le_bytes(bytes.try_into().expect("bounded lenenc field")),
        )
    } else {
        read_length_encoded_number(i)?
    };
    if size > 65_535 {
        return Err(nom::Err::Failure(nom::error::Error::new(
            i,
            nom::error::ErrorKind::TooLarge,
        )));
    }
    // Native authentication validates the outer blob only. Internal malformed
    // lenenc fields are retained for the bounded PFS row reader.
    let (remaining, attrs_bytes) = nom::bytes::complete::take(size)(i)?;
    Ok((remaining, attrs_bytes.to_vec()))
}

fn read_length_encoded_number(i: &[u8]) -> nom::IResult<&[u8], u64> {
    let (i, b) = nom::number::complete::le_u8(i)?;
    let size: usize = match b {
        0xfb => return Ok((i, 0)),
        0xfc => 2,
        0xfd => 3,
        0xfe => 8,
        _ => return Ok((i, b as u64)),
    };
    let mut bytes = [0u8; 8];
    let (i, b) = nom::bytes::complete::take(size)(i)?;
    bytes[..size].copy_from_slice(b);
    Ok((i, u64::from_le_bytes(bytes)))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command<'a> {
    Query(&'a [u8]),
    ListFields(&'a [u8]),
    CreateDatabase(&'a [u8]),
    DropDatabase(&'a [u8]),
    Refresh(u8),
    Shutdown,
    Statistics,
    ProcessInfo,
    ProcessKill(u32),
    Debug,
    TableDump(&'a [u8]),
    SetOption(u16),
    Close(u32),
    Prepare(&'a [u8]),
    Init(&'a [u8]),
    Execute {
        stmt: u32,
        flags: u8,
        params: &'a [u8],
    },
    SendLongData {
        stmt: u32,
        param: u16,
        data: &'a [u8],
    },
    ResetStatement(u32),
    Fetch {
        stmt: u32,
        rows: u32,
    },
    ResetConnection,
    ChangeUser(&'a [u8]),
    Ping,
    Quit,
    /// A command byte not implemented by this server.  Keeping it explicit
    /// lets the wire loop return ER_UNKNOWN_COM_ERROR instead of a misleading
    /// OK packet.
    Unknown(u8),
}

pub fn execute(i: &[u8]) -> nom::IResult<&[u8], Command<'_>> {
    let (i, stmt) = nom::number::complete::le_u32(i)?;
    let (i, flags) = nom::number::complete::le_u8(i)?;
    let (i, _iterations) = nom::number::complete::le_u32(i)?;
    Ok((
        &[],
        Command::Execute {
            stmt,
            flags,
            params: i,
        },
    ))
}

pub fn fetch(i: &[u8]) -> nom::IResult<&[u8], Command<'_>> {
    let (i, stmt) = nom::number::complete::le_u32(i)?;
    let (i, rows) = nom::number::complete::le_u32(i)?;
    Ok((i, Command::Fetch { stmt, rows }))
}

pub fn send_long_data(i: &[u8]) -> nom::IResult<&[u8], Command<'_>> {
    let (i, stmt) = nom::number::complete::le_u32(i)?;
    let (i, param) = nom::number::complete::le_u16(i)?;
    Ok((
        &[],
        Command::SendLongData {
            stmt,
            param,
            data: i,
        },
    ))
}

pub fn parse(i: &[u8]) -> nom::IResult<&[u8], Command<'_>> {
    let Some((&command, payload)) = i.split_first() else {
        return Err(nom::Err::Error(nom::error::Error::new(
            i,
            nom::error::ErrorKind::Eof,
        )));
    };
    let parsed = match command {
        value if value == CommandByte::COM_QUERY as u8 => Command::Query(payload),
        value if value == CommandByte::COM_FIELD_LIST as u8 => Command::ListFields(payload),
        value if value == CommandByte::COM_CREATE_DB as u8 => Command::CreateDatabase(payload),
        value if value == CommandByte::COM_DROP_DB as u8 => Command::DropDatabase(payload),
        value if value == CommandByte::COM_REFRESH as u8 => {
            let flag = payload.first().copied().ok_or_else(|| {
                nom::Err::Error(nom::error::Error::new(payload, nom::error::ErrorKind::Eof))
            })?;
            Command::Refresh(flag)
        }
        // mysql_common calls command byte 8 COM_DEPRECATED_1; in MySQL 8.0
        // this is the legacy COM_SHUTDOWN wire value.
        value if value == CommandByte::COM_DEPRECATED_1 as u8 => Command::Shutdown,
        value if value == CommandByte::COM_STATISTICS as u8 => Command::Statistics,
        value if value == CommandByte::COM_PROCESS_INFO as u8 => Command::ProcessInfo,
        value if value == CommandByte::COM_PROCESS_KILL as u8 => {
            let (_, id) = nom::number::complete::le_u32(payload)?;
            Command::ProcessKill(id)
        }
        value if value == CommandByte::COM_DEBUG as u8 => Command::Debug,
        value if value == CommandByte::COM_TABLE_DUMP as u8 => Command::TableDump(payload),
        value if value == CommandByte::COM_SET_OPTION as u8 => {
            let (_, option) = nom::number::complete::le_u16(payload)?;
            Command::SetOption(option)
        }
        value if value == CommandByte::COM_INIT_DB as u8 => Command::Init(payload),
        value if value == CommandByte::COM_STMT_PREPARE as u8 => Command::Prepare(payload),
        value if value == CommandByte::COM_STMT_EXECUTE as u8 => return execute(payload),
        value if value == CommandByte::COM_STMT_SEND_LONG_DATA as u8 => {
            return send_long_data(payload);
        }
        value if value == CommandByte::COM_STMT_RESET as u8 => {
            let (remaining, statement) = nom::number::complete::le_u32(payload)?;
            return Ok((remaining, Command::ResetStatement(statement)));
        }
        value if value == CommandByte::COM_STMT_FETCH as u8 => return fetch(payload),
        value if value == CommandByte::COM_STMT_CLOSE as u8 => {
            let (remaining, statement) = nom::number::complete::le_u32(payload)?;
            return Ok((remaining, Command::Close(statement)));
        }
        value if value == CommandByte::COM_QUIT as u8 => Command::Quit,
        value if value == CommandByte::COM_PING as u8 => Command::Ping,
        value if value == CommandByte::COM_RESET_CONNECTION as u8 => Command::ResetConnection,
        value if value == CommandByte::COM_CHANGE_USER as u8 => Command::ChangeUser(payload),
        value => Command::Unknown(value),
    };
    Ok((&[], parsed))
}
