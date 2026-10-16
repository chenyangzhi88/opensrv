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

use std::io::{self, Write};

use crate::myc::constants::{CapabilityFlags, StatusFlags};
use crate::myc::io::WriteMysqlExt;
use crate::packet_writer::PacketWriter;
use crate::{Column, ColumnFlags, ColumnType, ErrorKind, OkResponse};
use byteorder::{LittleEndian, WriteBytesExt};
use tokio::io::AsyncWrite;

const BIN_GENERAL_CI: u16 = 0x3f;

pub(crate) fn column_charset(column: &Column) -> u16 {
    use crate::myc::constants::UTF8_GENERAL_CI;

    if let Some(charset) = column.charset {
        return charset;
    }

    if column
        .colflags
        .intersects(ColumnFlags::BINARY_FLAG | ColumnFlags::BLOB_FLAG)
        || matches!(
            column.coltype,
            ColumnType::MYSQL_TYPE_TINY_BLOB
                | ColumnType::MYSQL_TYPE_BLOB
                | ColumnType::MYSQL_TYPE_MEDIUM_BLOB
                | ColumnType::MYSQL_TYPE_LONG_BLOB
                | ColumnType::MYSQL_TYPE_GEOMETRY
        )
    {
        return BIN_GENERAL_CI;
    }

    if matches!(
        column.coltype,
        ColumnType::MYSQL_TYPE_STRING
            | ColumnType::MYSQL_TYPE_VAR_STRING
            | ColumnType::MYSQL_TYPE_VARCHAR
            | ColumnType::MYSQL_TYPE_ENUM
            | ColumnType::MYSQL_TYPE_SET
            | ColumnType::MYSQL_TYPE_JSON
    ) {
        UTF8_GENERAL_CI
    } else {
        BIN_GENERAL_CI
    }
}

pub(crate) async fn write_eof_packet<W: AsyncWrite + Unpin>(
    w: &mut PacketWriter<W>,
    s: StatusFlags,
    warnings: u16,
) -> io::Result<()> {
    w.write_all(&[0xFE])?;
    w.write_u16::<LittleEndian>(warnings)?;
    w.write_u16::<LittleEndian>(s.bits())?;
    w.end_packet().await
}

pub(crate) async fn write_ok_packet<W: AsyncWrite + Unpin>(
    w: &mut PacketWriter<W>,
    client_capabilities: CapabilityFlags,
    ok_packet: OkResponse,
) -> io::Result<()> {
    w.write_u8(ok_packet.header)?; // OK packet type
    w.write_lenenc_int(ok_packet.affected_rows)?;
    w.write_lenenc_int(ok_packet.last_insert_id)?;
    if client_capabilities.contains(CapabilityFlags::CLIENT_PROTOCOL_41) {
        w.write_u16::<LittleEndian>(ok_packet.status_flags.bits())?;
        w.write_u16::<LittleEndian>(ok_packet.warnings)?;
    } else if client_capabilities.contains(CapabilityFlags::CLIENT_TRANSACTIONS) {
        w.write_u16::<LittleEndian>(ok_packet.status_flags.bits())?;
    }

    // MySQL emits OK info as a length-encoded string. Current MySQL clients
    // parse this form even without CLIENT_SESSION_TRACK (matching
    // net_send_ok), and result-set terminators use the same encoding.
    let has_session_track = client_capabilities.contains(CapabilityFlags::CLIENT_SESSION_TRACK);
    let send_info = !ok_packet.info.is_empty() || has_session_track;
    if send_info {
        w.write_lenenc_str(ok_packet.info.as_bytes())?;
    }

    // Session state info is optional and only sent if flag is set
    if has_session_track
        && ok_packet
            .status_flags
            .contains(StatusFlags::SERVER_SESSION_STATE_CHANGED)
    {
        w.write_lenenc_str(&ok_packet.session_state_info)?;
    }
    w.end_packet().await
}

pub async fn write_err<W: AsyncWrite + Unpin>(
    err: ErrorKind,
    msg: &[u8],
    w: &mut PacketWriter<W>,
) -> io::Result<()> {
    write_err_raw(err as u16, err.sqlstate(), msg, w).await
}

pub async fn write_err_raw<W: AsyncWrite + Unpin>(
    code: u16,
    sqlstate: &[u8; 5],
    msg: &[u8],
    w: &mut PacketWriter<W>,
) -> io::Result<()> {
    w.write_u8(0xFF)?;
    w.write_u16::<LittleEndian>(code)?;
    w.write_u8(b'#')?;
    w.write_all(sqlstate)?;
    w.write_all(msg)?;
    w.end_packet().await
}

pub(crate) async fn write_prepare_ok<'a, PI, CI, W>(
    id: u32,
    params: PI,
    columns: CI,
    warnings: u16,
    w: &mut PacketWriter<W>,
    client_capabilities: CapabilityFlags,
    send_metadata: bool,
) -> io::Result<()>
where
    PI: IntoIterator<Item = &'a Column>,
    CI: IntoIterator<Item = &'a Column>,
    <PI as IntoIterator>::IntoIter: ExactSizeIterator,
    <CI as IntoIterator>::IntoIter: ExactSizeIterator,
    W: AsyncWrite + Unpin,
{
    let pi = params.into_iter();
    let ci = columns.into_iter();

    // first, write out COM_STMT_PREPARE_OK
    w.write_u8(0x00)?;
    w.write_u32::<LittleEndian>(id)?;
    w.write_u16::<LittleEndian>(ci.len() as u16)?;
    w.write_u16::<LittleEndian>(pi.len() as u16)?;
    w.write_u8(0x00)?;
    w.write_u16::<LittleEndian>(warnings)?;
    if client_capabilities.contains(CapabilityFlags::CLIENT_OPTIONAL_RESULTSET_METADATA) {
        w.write_u8(u8::from(send_metadata))?;
    }
    w.end_packet().await?;

    if send_metadata && pi.len() > 0 {
        write_column_definitions_41(pi, w, client_capabilities, false).await?;
    }
    if send_metadata && ci.len() > 0 {
        write_column_definitions_41(ci, w, client_capabilities, false).await?;
    }
    Ok(())
}

/// works for Protocol::ColumnDefinition41 is set
/// see: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset_column_definition.html
pub(crate) async fn write_column_definitions_41<'a, I, W>(
    i: I,
    w: &mut PacketWriter<W>,
    client_capabilities: CapabilityFlags,
    is_com_field_list: bool,
) -> io::Result<()>
where
    I: IntoIterator<Item = &'a Column>,
    W: AsyncWrite + Unpin,
{
    write_column_definitions_41_with_defaults(i, w, client_capabilities, is_com_field_list, None)
        .await
}

pub(crate) async fn write_column_definitions_41_with_defaults<'a, I, W>(
    i: I,
    w: &mut PacketWriter<W>,
    client_capabilities: CapabilityFlags,
    is_com_field_list: bool,
    field_defaults: Option<&[Option<Vec<u8>>]>,
) -> io::Result<()>
where
    I: IntoIterator<Item = &'a Column>,
    W: AsyncWrite + Unpin,
{
    write_column_definitions_41_with_defaults_and_status(
        i,
        w,
        client_capabilities,
        is_com_field_list,
        field_defaults,
        StatusFlags::empty(),
        0,
    )
    .await
}

pub(crate) async fn write_column_definitions_41_with_defaults_and_status<'a, I, W>(
    i: I,
    w: &mut PacketWriter<W>,
    client_capabilities: CapabilityFlags,
    is_com_field_list: bool,
    field_defaults: Option<&[Option<Vec<u8>>]>,
    status: StatusFlags,
    warnings: u16,
) -> io::Result<()>
where
    I: IntoIterator<Item = &'a Column>,
    W: AsyncWrite + Unpin,
{
    for (column_index, c) in i.into_iter().enumerate() {
        w.write_lenenc_str(b"def")?;
        w.write_lenenc_str(&c.database)?;
        w.write_lenenc_str(&c.table)?;
        w.write_lenenc_str(&c.org_table)?;
        w.write_lenenc_str(&c.column)?;
        w.write_lenenc_str(&c.org_column)?;
        w.write_lenenc_int(0xC)?;
        w.write_u16::<LittleEndian>(column_charset(c))?;
        w.write_u32::<LittleEndian>(c.collen)?;
        w.write_u8(c.coltype as u8)?;
        w.write_u16::<LittleEndian>(c.colflags.bits())?;
        w.write_all(&[c.decimals.unwrap_or(0)])?; // decimals
        w.write_all(&[0x00, 0x00])?; // unused

        if is_com_field_list {
            if let Some(default) = field_defaults
                .and_then(|defaults| defaults.get(column_index))
                .and_then(Option::as_ref)
            {
                w.write_lenenc_str(default)?;
            } else {
                w.write_all(&[0xfb])?;
            }
        }
        w.end_packet().await?;
    }

    // COM_FIELD_LIST is a legacy stream with no column-count packet, so a
    // terminator is always required. With CLIENT_DEPRECATE_EOF, libmysql
    // parses that terminator as an OK packet whose header is 0xFE.
    if is_com_field_list && client_capabilities.contains(CapabilityFlags::CLIENT_DEPRECATE_EOF) {
        write_ok_packet(
            w,
            client_capabilities,
            OkResponse {
                header: 0xfe,
                status_flags: status,
                warnings,
                ..OkResponse::default()
            },
        )
        .await
    } else if is_com_field_list
        || !client_capabilities.contains(CapabilityFlags::CLIENT_DEPRECATE_EOF)
    {
        write_eof_packet(w, status, warnings).await
    } else {
        Ok(())
    }
}

pub(crate) async fn column_definitions_with_metadata<'a, I, W>(
    i: I,
    w: &mut PacketWriter<W>,
    client_capabilities: CapabilityFlags,
    send_metadata: bool,
) -> io::Result<()>
where
    I: IntoIterator<Item = &'a Column>,
    <I as IntoIterator>::IntoIter: ExactSizeIterator,
    W: AsyncWrite + Unpin,
{
    let i = i.into_iter();
    w.write_lenenc_int(i.len() as u64)?;
    if client_capabilities.contains(CapabilityFlags::CLIENT_OPTIONAL_RESULTSET_METADATA) {
        w.write_u8(u8::from(send_metadata))?;
    }
    w.end_packet().await?;
    if send_metadata {
        write_column_definitions_41(i, w, client_capabilities, false).await
    } else {
        Ok(())
    }
}
