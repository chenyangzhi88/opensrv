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

use std::borrow::{Borrow, Cow};
use std::collections::HashMap;
use std::io::{self, Write};

use byteorder::WriteBytesExt;
use mysql_common::constants::{CapabilityFlags, ColumnFlags, StatusFlags};
use tokio::io::AsyncWrite;

use crate::packet_writer::PacketWriter;
use crate::value::ToMysqlValue;
use crate::{writers, OkResponse};
use crate::{Column, ErrorKind, StatementData};

/// Convenience type for responding to a client `USE <db>` command.
pub struct InitWriter<'a, W> {
    pub(crate) client_capabilities: CapabilityFlags,
    pub(crate) writer: &'a mut PacketWriter<W>,
}

impl<'a, W: 'a + AsyncWrite + Unpin> InitWriter<'a, W> {
    /// Tell client that database context has been changed
    pub async fn ok(self) -> io::Result<()> {
        writers::write_ok_packet(self.writer, self.client_capabilities, OkResponse::default()).await
    }

    /// Tell the client that the database context changed while preserving
    /// backend-owned status, warnings and session tracking information.
    pub async fn ok_with_response(self, response: OkResponse) -> io::Result<()> {
        writers::write_ok_packet(self.writer, self.client_capabilities, response).await
    }

    /// Tell client that there was a problem changing the database context.
    /// Although you can return any valid MySQL error code you probably want
    /// to keep it similar to the MySQL server and issue either a
    /// `ErrorKind::ER_BAD_DB_ERROR` or a `ErrorKind::ER_DBACCESS_DENIED_ERROR`.
    pub async fn error<E>(self, kind: ErrorKind, msg: &E) -> io::Result<()>
    where
        E: Borrow<[u8]> + ?Sized,
    {
        writers::write_err(kind, msg.borrow(), self.writer).await
    }

    pub async fn error_raw<E>(self, code: u16, sqlstate: &[u8; 5], msg: &E) -> io::Result<()>
    where
        E: Borrow<[u8]> + ?Sized,
    {
        writers::write_err_raw(code, sqlstate, msg.borrow(), self.writer).await
    }
}

/// Convenience type for responding to a client `PREPARE` command.
///
/// This type should not be dropped without calling
/// [`reply`](struct.StatementMetaWriter.html#method.reply) or
/// [`error`](struct.StatementMetaWriter.html#method.error).
#[must_use]
pub struct StatementMetaWriter<'a, W> {
    pub(crate) writer: &'a mut PacketWriter<W>,
    pub(crate) stmts: &'a mut HashMap<u32, StatementData>,
    pub(crate) client_capabilities: CapabilityFlags,
}

impl<'a, W: AsyncWrite + Unpin + 'a> StatementMetaWriter<'a, W> {
    /// Reply to the client with the given meta-information.
    ///
    /// `id` is a statement identifier that the client should supply when it later wants to execute
    /// this statement. `params` is a set of [`Column`](struct.Column.html) descriptors for the
    /// parameters the client must provide when executing the prepared statement. `columns` is a
    /// second set of [`Column`](struct.Column.html) descriptors for the values that will be
    /// returned in each row then the statement is later executed.
    pub async fn reply<PI, CI>(self, id: u32, params: PI, columns: CI) -> io::Result<()>
    where
        PI: IntoIterator<Item = &'a Column>,
        CI: IntoIterator<Item = &'a Column>,
        <PI as IntoIterator>::IntoIter: ExactSizeIterator,
        <CI as IntoIterator>::IntoIter: ExactSizeIterator,
    {
        self.reply_with_warnings(id, params, columns, 0).await
    }

    /// Reply to `COM_STMT_PREPARE`, including diagnostics raised while the
    /// server derived statement metadata.
    pub async fn reply_with_warnings<PI, CI>(
        self,
        id: u32,
        params: PI,
        columns: CI,
        warnings: u16,
    ) -> io::Result<()>
    where
        PI: IntoIterator<Item = &'a Column>,
        CI: IntoIterator<Item = &'a Column>,
        <PI as IntoIterator>::IntoIter: ExactSizeIterator,
        <CI as IntoIterator>::IntoIter: ExactSizeIterator,
    {
        self.reply_with_warnings_and_metadata(id, params, columns, warnings, true)
            .await
    }

    pub async fn reply_with_warnings_and_metadata<PI, CI>(
        self,
        id: u32,
        params: PI,
        columns: CI,
        warnings: u16,
        send_metadata: bool,
    ) -> io::Result<()>
    where
        PI: IntoIterator<Item = &'a Column>,
        CI: IntoIterator<Item = &'a Column>,
        <PI as IntoIterator>::IntoIter: ExactSizeIterator,
        <CI as IntoIterator>::IntoIter: ExactSizeIterator,
    {
        let params = params.into_iter();
        let Ok(parameter_count) = u16::try_from(params.len()) else {
            return writers::write_err(
                ErrorKind::ER_PS_MANY_PARAM,
                b"Prepared statement contains too many placeholders",
                self.writer,
            )
            .await;
        };
        self.stmts.insert(
            id,
            StatementData {
                params: parameter_count,
                ..Default::default()
            },
        );
        writers::write_prepare_ok(
            id,
            params,
            columns,
            warnings,
            self.writer,
            self.client_capabilities,
            send_metadata,
        )
        .await
    }

    /// Reply to the client's `PREPARE` with an error.
    pub async fn error<E>(self, kind: ErrorKind, msg: &E) -> io::Result<()>
    where
        E: Borrow<[u8]> + ?Sized,
    {
        writers::write_err(kind, msg.borrow(), self.writer).await
    }

    pub async fn error_raw<E>(self, code: u16, sqlstate: &[u8; 5], msg: &E) -> io::Result<()>
    where
        E: Borrow<[u8]> + ?Sized,
    {
        writers::write_err_raw(code, sqlstate, msg.borrow(), self.writer).await
    }
}

enum Finalizer {
    Ok(OkResponse),
    Eof(StatusFlags, u16),
}

/// Convenience type for providing query results to clients.
///
/// This type should not be dropped without calling
/// [`start`](struct.QueryResultWriter.html#method.start),
/// [`completed`](struct.QueryResultWriter.html#method.completed), or
/// [`error`](struct.QueryResultWriter.html#method.error).
///
/// To send multiple resultsets, use
/// [`RowWriter::finish_one`](struct.RowWriter.html#method.finish_one) and
/// [`complete_one`](struct.QueryResultWriter.html#method.complete_one). These are similar to
/// `RowWriter::finish` and `completed`, but both eventually yield back the `QueryResultWriter` so
/// that another resultset can be sent. To indicate that no more resultset will be sent, call
/// [`no_more_results`](struct.QueryResultWriter.html#method.no_more_results). All methods on
/// `QueryResultWriter` (except `no_more_results`) automatically start a new resultset. The
#[must_use]
pub struct QueryResultWriter<'a, W> {
    // XXX: specialization instead?
    pub(crate) is_bin: bool,
    pub(crate) client_capabilities: CapabilityFlags,
    pub(crate) writer: &'a mut PacketWriter<W>,
    last_end: Option<Finalizer>,
}

impl<'a, W: AsyncWrite + Unpin> QueryResultWriter<'a, W> {
    pub(crate) fn new(
        writer: &'a mut PacketWriter<W>,
        is_bin: bool,
        client_capabilities: CapabilityFlags,
    ) -> Self {
        QueryResultWriter {
            is_bin,
            client_capabilities,
            writer,
            last_end: None,
        }
    }

    async fn finalize(&mut self, more_exists: bool) -> io::Result<()> {
        let mut status = StatusFlags::empty();
        if more_exists {
            status.set(StatusFlags::SERVER_MORE_RESULTS_EXISTS, true);
        }
        match self.last_end.take() {
            None => Ok(()),
            Some(Finalizer::Ok(mut ok_packet)) => {
                if more_exists {
                    ok_packet
                        .status_flags
                        .set(StatusFlags::SERVER_MORE_RESULTS_EXISTS, true);
                }
                writers::write_ok_packet(self.writer, self.client_capabilities, ok_packet).await
            }
            Some(Finalizer::Eof(mut final_status, warnings)) => {
                final_status.insert(status);
                writers::write_eof_packet(self.writer, final_status, warnings).await
            }
        }
    }

    /// Start a resultset response to the client that conforms to the given `columns`.
    ///
    /// Note that if no columns are emitted, any written rows are ignored.
    ///
    /// See [`RowWriter`](struct.RowWriter.html).
    pub async fn start<'columns>(
        mut self,
        columns: &'columns [Column],
    ) -> io::Result<RowWriter<'a, 'columns, W>> {
        self.finalize(true).await?;
        RowWriter::new(self, Cow::Borrowed(columns), true).await
    }

    /// Start a resultset whose column count remains present while column
    /// definitions are omitted under CLIENT_OPTIONAL_RESULTSET_METADATA.
    pub async fn start_without_metadata<'columns>(
        mut self,
        columns: &'columns [Column],
    ) -> io::Result<RowWriter<'a, 'columns, W>> {
        self.finalize(true).await?;
        RowWriter::new(self, Cow::Borrowed(columns), false).await
    }

    /// Start a resultset with the column allocation moved into the same row writer.
    /// The owned columns may outlive the producing call without borrowing its stack.
    pub async fn start_owned(
        mut self,
        columns: Vec<Column>,
    ) -> io::Result<RowWriter<'a, 'static, W>> {
        self.finalize(true).await?;
        RowWriter::new(self, Cow::Owned(columns), true).await
    }

    /// Start an owned-column resultset while omitting optional column definitions.
    pub async fn start_without_metadata_owned(
        mut self,
        columns: Vec<Column>,
    ) -> io::Result<RowWriter<'a, 'static, W>> {
        self.finalize(true).await?;
        RowWriter::new(self, Cow::Owned(columns), false).await
    }

    /// Reply to COM_FIELD_LIST with ColumnDefinition41 packets and no
    /// result-set column-count packet. The legacy command also carries an
    /// extra default-value field in every column definition.
    pub async fn field_list(mut self, columns: &[Column]) -> io::Result<()> {
        self.finalize(false).await?;
        writers::write_column_definitions_41(columns, self.writer, self.client_capabilities, true)
            .await
    }

    /// Reply to COM_FIELD_LIST and include the legacy per-column default
    /// value. A `None` entry is encoded as SQL NULL.
    pub async fn field_list_with_defaults(
        mut self,
        columns: &[Column],
        defaults: &[Option<Vec<u8>>],
    ) -> io::Result<()> {
        self.finalize(false).await?;
        writers::write_column_definitions_41_with_defaults(
            columns,
            self.writer,
            self.client_capabilities,
            true,
            Some(defaults),
        )
        .await
    }

    /// Reply to COM_FIELD_LIST and publish the command's status and warnings in its EOF packet.
    pub async fn field_list_with_defaults_and_status(
        mut self,
        columns: &[Column],
        defaults: &[Option<Vec<u8>>],
        status: StatusFlags,
        warnings: u16,
    ) -> io::Result<()> {
        self.finalize(false).await?;
        writers::write_column_definitions_41_with_defaults_and_status(
            columns,
            self.writer,
            self.client_capabilities,
            true,
            Some(defaults),
            status,
            warnings,
        )
        .await
    }

    /// Send an empty resultset response to the client indicating that `rows` rows were affected by
    /// the query in this resultset. `last_insert_id` may be given to communiate an identifier for
    /// a client's most recent insertion.
    pub async fn complete_one(
        mut self,
        ok_packet: OkResponse,
    ) -> io::Result<QueryResultWriter<'a, W>> {
        self.finalize(true).await?;
        self.last_end = Some(Finalizer::Ok(ok_packet));
        Ok(self)
    }

    /// Send an empty resultset response to the client indicating that `rows` rows were affected by
    /// the query. `last_insert_id` may be given to communiate an identifier for a client's most
    /// recent insertion.
    pub async fn completed(self, ok_packet: OkResponse) -> io::Result<()> {
        self.complete_one(ok_packet).await?.no_more_results().await
    }

    /// Reply to the client's query with an error.
    pub async fn error<E>(mut self, kind: ErrorKind, msg: &E) -> io::Result<()>
    where
        E: Borrow<[u8]> + ?Sized,
    {
        self.finalize(true).await?;
        writers::write_err(kind, msg.borrow(), self.writer).await
    }

    pub async fn error_raw<E>(mut self, code: u16, sqlstate: &[u8; 5], msg: &E) -> io::Result<()>
    where
        E: Borrow<[u8]> + ?Sized,
    {
        self.finalize(true).await?;
        writers::write_err_raw(code, sqlstate, msg.borrow(), self.writer).await
    }

    /// Send the last bits of the last resultset to the client, and indicate that there are no more
    /// resultsets coming.
    pub async fn no_more_results(mut self) -> io::Result<()> {
        self.finalize(false).await
    }

    /// Publish a completed result immediately and mark that another result or error follows.
    pub async fn flush_more_results(mut self) -> io::Result<Self> {
        self.finalize(true).await?;
        self.writer.flush_all().await?;
        Ok(self)
    }

    /// Send cursor metadata without row data after COM_STMT_EXECUTE while preserving the current
    /// server transaction state.
    pub async fn cursor_open<'columns>(
        mut self,
        columns: &'columns [Column],
        mut response: OkResponse,
    ) -> io::Result<()> {
        self.finalize(true).await?;
        // Write the column count and definitions, but own the terminator below so it can carry
        // SERVER_STATUS_CURSOR_EXISTS. Without this mask legacy EOF clients would receive two
        // terminators and lose cursor state.
        writers::column_definitions(
            columns,
            self.writer,
            self.client_capabilities | CapabilityFlags::CLIENT_DEPRECATE_EOF,
        )
        .await?;
        response
            .status_flags
            .insert(StatusFlags::SERVER_STATUS_CURSOR_EXISTS);
        if self
            .client_capabilities
            .contains(CapabilityFlags::CLIENT_DEPRECATE_EOF)
        {
            response.header = 0xfe;
            writers::write_ok_packet(self.writer, self.client_capabilities, response).await
        } else {
            writers::write_eof_packet(self.writer, response.status_flags, response.warnings).await
        }
    }

    /// Start a COM_STMT_FETCH response; cursor fetch packets omit column definitions.
    pub async fn start_cursor_fetch<'columns>(
        mut self,
        columns: &'columns [Column],
    ) -> io::Result<RowWriter<'a, 'columns, W>> {
        self.finalize(true).await?;
        RowWriter::new_without_definitions(self, columns).await
    }
}

/// Convenience type for sending rows of a resultset to a client.
///
/// Rows can either be written out one column at a time (using
/// [`write_col`](struct.RowWriter.html#method.write_col) and
/// [`end_row`](struct.RowWriter.html#method.end_row)), or one row at a time (using
/// [`write_row`](struct.RowWriter.html#method.write_row)).
///
/// Dropping this type does not perform IO or complete the resultset. Call an
/// explicit finish method for a successful result or an error method for a
/// terminal SQL error. An abandoned transport remains the connection owner's
/// responsibility.
#[must_use]
pub struct RowWriter<'a, 'columns, W: AsyncWrite + Unpin> {
    client_capabilities: CapabilityFlags,
    result: Option<QueryResultWriter<'a, W>>,
    bitmap_len: usize,
    data: Vec<u8>,
    columns: Cow<'columns, [Column]>,

    // next column to write for the current row
    // NOTE: (ab)used to track number of *rows* for a zero-column resultset
    col: usize,
    finished: bool,
}

impl<'a, 'columns, W> RowWriter<'a, 'columns, W>
where
    W: 'a + AsyncWrite + Unpin,
{
    async fn new(
        result: QueryResultWriter<'a, W>,
        columns: Cow<'columns, [Column]>,
        send_metadata: bool,
    ) -> io::Result<RowWriter<'a, 'columns, W>> {
        let bitmap_len = (columns.len() + 7 + 2) / 8;
        let client_capabilities = result.client_capabilities;
        let mut rw = RowWriter {
            client_capabilities,
            result: Some(result),
            columns,
            bitmap_len,
            data: Vec::new(),

            col: 0,

            finished: false,
        };
        rw.start(send_metadata).await?;
        Ok(rw)
    }

    async fn new_without_definitions(
        result: QueryResultWriter<'a, W>,
        columns: &'columns [Column],
    ) -> io::Result<RowWriter<'a, 'columns, W>> {
        let bitmap_len = (columns.len() + 7 + 2) / 8;
        Ok(RowWriter {
            client_capabilities: result.client_capabilities,
            result: Some(result),
            columns: Cow::Borrowed(columns),
            bitmap_len,
            data: Vec::new(),
            col: 0,
            finished: false,
        })
    }

    #[inline]
    async fn start(&mut self, send_metadata: bool) -> io::Result<()> {
        if !self.columns.is_empty() {
            writers::column_definitions_with_metadata(
                self.columns.as_ref(),
                self.result.as_mut().unwrap().writer,
                self.client_capabilities,
                send_metadata,
            )
            .await?;
        }

        Ok(())
    }

    /// Flush metadata and completed rows without ending the resultset.
    /// An unfinished row must first be completed with `end_row`; no EOF/OK is sent.
    /// A transport error is returned to the connection owner, not converted to success.
    pub async fn flush_progress(&mut self) -> io::Result<()> {
        if !self.columns.is_empty() && self.col != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot flush progress during an unfinished row",
            ));
        }
        self.result.as_mut().unwrap().writer.flush_all().await
    }

    /// Write a value to the next column of the current row as a part of this resultset.
    ///
    /// If you do not call [`end_row`](struct.RowWriter.html#method.end_row) after the last row,
    /// any errors that occur when writing out the last row will be returned by
    /// [`finish`](struct.RowWriter.html#method.finish). Drop neither writes nor completes it.
    ///
    /// Note that the row *must* conform to the column specification provided to
    /// [`QueryResultWriter::start`](struct.QueryResultWriter.html#method.start). If it does not,
    /// this method will return an error indicating that an invalid value type or specification was
    /// provided.
    pub fn write_col<T>(&mut self, v: T) -> io::Result<()>
    where
        T: ToMysqlValue,
    {
        if self.columns.is_empty() {
            return Ok(());
        }

        if self.result.as_mut().unwrap().is_bin {
            if self.col == 0 {
                self.result.as_mut().unwrap().writer.write_u8(0x00)?;

                // leave space for nullmap
                self.data.resize(self.bitmap_len, 0);
            }

            let c = self.columns.get(self.col).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "row has more columns than specification",
                )
            })?;
            if v.is_null() {
                if c.colflags.contains(ColumnFlags::NOT_NULL_FLAG) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "given NULL value for NOT NULL column",
                    ));
                } else {
                    // https://web.archive.org/web/20170404144156/https://dev.mysql.com/doc/internals/en/null-bitmap.html
                    // NULL-bitmap-byte = ((field-pos + offset) / 8)
                    // NULL-bitmap-bit  = ((field-pos + offset) % 8)
                    self.data[(self.col + 2) / 8] |= 1u8 << ((self.col + 2) % 8);
                }
            } else {
                v.to_mysql_bin(&mut self.data, c)?;
            }
        } else {
            v.to_mysql_text(self.result.as_mut().unwrap().writer)?;
        }
        self.col += 1;
        Ok(())
    }

    /// Indicate that no more column data will be written for the current row.
    pub async fn end_row(&mut self) -> io::Result<()> {
        if self.columns.is_empty() {
            self.col += 1;
            return Ok(());
        }

        if self.col != self.columns.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "row has fewer columns than specification",
            ));
        }

        if self.result.as_mut().unwrap().is_bin {
            self.result
                .as_mut()
                .unwrap()
                .writer
                .write_all(&self.data[..])?;
            self.data.clear();
        }
        self.result.as_mut().unwrap().writer.end_packet().await?;
        self.col = 0;

        Ok(())
    }

    /// Write a single row as a part of this resultset.
    ///
    /// Note that the row *must* conform to the column specification provided to
    /// [`QueryResultWriter::start`](struct.QueryResultWriter.html#method.start). If it does not,
    /// this method will return an error indicating that an invalid value type or specification was
    /// provided.
    pub async fn write_row<I, E>(&mut self, row: I) -> io::Result<()>
    where
        I: IntoIterator<Item = E>,
        E: ToMysqlValue,
    {
        if !self.columns.is_empty() {
            for v in row {
                self.write_col(v)?;
            }
        }
        self.end_row().await
    }
}

impl<'a, 'columns, W: AsyncWrite + Unpin + 'a> RowWriter<'a, 'columns, W> {
    async fn finish_inner(&mut self, extra_info: &str, complete: bool) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }

        self.finished = true;

        if !self.columns.is_empty() && self.col != 0 {
            self.end_row().await?;
        }

        if complete {
            if self.columns.is_empty() {
                let resp = OkResponse {
                    info: extra_info.to_string(),
                    ..Default::default()
                };
                self.result.as_mut().unwrap().last_end = Some(Finalizer::Ok(resp));
            } else if self
                .client_capabilities
                .contains(CapabilityFlags::CLIENT_DEPRECATE_EOF)
            {
                // With CLIENT_DEPRECATE_EOF the server must terminate the resultset with an OK packet (header 0xFE).
                let resp = OkResponse {
                    header: 0xfe,
                    info: extra_info.to_string(),
                    ..Default::default()
                };
                self.result.as_mut().unwrap().last_end = Some(Finalizer::Ok(resp));
            } else {
                // we wrote out at least one row
                self.result.as_mut().unwrap().last_end =
                    Some(Finalizer::Eof(StatusFlags::empty(), 0));
            }
        }

        Ok(())
    }

    /// Indicate to the client that no more rows are coming.
    pub async fn finish(self) -> io::Result<()> {
        self.finish_with_info("").await
    }

    /// End this resultset response, and indicate to the client that no more rows are coming.
    pub async fn finish_one(self) -> io::Result<QueryResultWriter<'a, W>> {
        self.finish_one_with_info("").await
    }

    /// Indicate to the client that no more rows are coming.
    pub async fn finish_with_info(self, extra_info: &str) -> io::Result<()> {
        self.finish_one_with_info(extra_info)
            .await?
            .no_more_results()
            .await
    }

    /// Finish a resultset while preserving server transaction/autocommit status.
    pub async fn finish_with_status(self, status: StatusFlags) -> io::Result<()> {
        self.finish_one_with_status(status)
            .await?
            .no_more_results()
            .await
    }

    /// Finish one resultset while preserving server transaction/autocommit status.
    pub async fn finish_one_with_status(
        mut self,
        status: StatusFlags,
    ) -> io::Result<QueryResultWriter<'a, W>> {
        self.finish_inner("", true).await?;
        match self
            .result
            .as_mut()
            .and_then(|result| result.last_end.as_mut())
        {
            Some(Finalizer::Ok(response)) => response.status_flags.insert(status),
            Some(Finalizer::Eof(response_status, _)) => response_status.insert(status),
            None => {}
        }
        Ok(self.result.take().unwrap())
    }

    /// Finish one result set and publish both status flags and the statement
    /// warning count in the terminating EOF/OK packet.
    pub async fn finish_one_with_status_and_warnings(
        mut self,
        status: StatusFlags,
        warnings: u16,
        session_state_info: Vec<u8>,
    ) -> io::Result<QueryResultWriter<'a, W>> {
        self.finish_inner("", true).await?;
        match self
            .result
            .as_mut()
            .and_then(|result| result.last_end.as_mut())
        {
            Some(Finalizer::Ok(response)) => {
                response.status_flags.insert(status);
                response.warnings = warnings;
                response.session_state_info = session_state_info;
            }
            Some(Finalizer::Eof(response_status, response_warnings)) => {
                response_status.insert(status);
                *response_warnings = warnings;
            }
            None => {}
        }
        Ok(self.result.take().unwrap())
    }

    /// Close an open partial result only after a stored-program handler was selected.
    /// Native handler boundaries use legacy EOF with zero warnings even when the
    /// client negotiated DEPRECATE_EOF. Normal result completion is unchanged.
    pub async fn finish_handled_partial(
        mut self,
        status: StatusFlags,
    ) -> io::Result<QueryResultWriter<'a, W>> {
        self.finish_inner("", false).await?;
        let result = self.result.take().unwrap();
        writers::write_eof_packet(result.writer, status, 0).await?;
        result.writer.flush_all().await?;
        Ok(result)
    }

    /// End this resultset response, and indicate to the client that no more rows are coming.
    pub async fn finish_one_with_info(
        mut self,
        extra_info: &str,
    ) -> io::Result<QueryResultWriter<'a, W>> {
        self.finish_inner(extra_info, true).await?;

        // we know that dropping self will see self.finished == true,
        // and so Drop won't try to use self.result.
        Ok(self.result.take().unwrap())
    }

    /// Finish one cursor fetch while preserving server transaction state. `last` reports
    /// SERVER_STATUS_LAST_ROW_SENT; otherwise the cursor remains open and
    /// SERVER_STATUS_CURSOR_EXISTS is preserved.
    pub async fn finish_cursor(self, last: bool, response: OkResponse) -> io::Result<()> {
        self.finish_cursor_one(last, response, false)
            .await
            .map(drop)
    }

    /// Finish a cursor result while retaining the writer so a stored
    /// procedure's following resultsets can be emitted after the last fetch.
    pub async fn finish_cursor_one(
        mut self,
        last: bool,
        mut response: OkResponse,
        more_results: bool,
    ) -> io::Result<QueryResultWriter<'a, W>> {
        self.finish_inner("", false).await?;
        response.status_flags.insert(if last {
            StatusFlags::SERVER_STATUS_LAST_ROW_SENT
        } else {
            StatusFlags::SERVER_STATUS_CURSOR_EXISTS
        });
        response
            .status_flags
            .set(StatusFlags::SERVER_MORE_RESULTS_EXISTS, more_results);
        let result = self.result.take().unwrap();
        if result
            .client_capabilities
            .contains(CapabilityFlags::CLIENT_DEPRECATE_EOF)
        {
            response.header = 0xfe;
            writers::write_ok_packet(result.writer, result.client_capabilities, response).await?;
        } else {
            writers::write_eof_packet(result.writer, response.status_flags, response.warnings)
                .await?;
        }
        Ok(result)
    }

    /// End this resultset response, and indicate to the client there was an error.
    pub async fn finish_error_one<E>(
        mut self,
        kind: ErrorKind,
        msg: &E,
    ) -> io::Result<QueryResultWriter<'a, W>>
    where
        E: Borrow<[u8]> + ?Sized,
    {
        self.finish_inner("", false).await?;
        let result = self.result.take().unwrap();
        writers::write_err(kind, msg.borrow(), result.writer).await?;
        Ok(result)
    }

    pub async fn finish_error_one_raw<E>(
        mut self,
        code: u16,
        sqlstate: &[u8; 5],
        msg: &E,
    ) -> io::Result<QueryResultWriter<'a, W>>
    where
        E: Borrow<[u8]> + ?Sized,
    {
        self.finish_inner("", false).await?;
        let result = self.result.take().unwrap();
        writers::write_err_raw(code, sqlstate, msg.borrow(), result.writer).await?;
        Ok(result)
    }

    /// End this resultset response, indicate an error, and close this response.
    pub async fn finish_error<E>(self, kind: ErrorKind, msg: &E) -> io::Result<()>
    where
        E: Borrow<[u8]> + ?Sized,
    {
        self.finish_error_one(kind, msg).await.map(drop)
    }

    pub async fn finish_error_raw<E>(self, code: u16, sqlstate: &[u8; 5], msg: &E) -> io::Result<()>
    where
        E: Borrow<[u8]> + ?Sized,
    {
        self.finish_error_one_raw(code, sqlstate, msg)
            .await
            .map(drop)
    }
}
