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

use byteorder::{LittleEndian, WriteBytesExt};

use crate::myc;
use crate::myc::constants::{ColumnFlags, ColumnType};
use crate::myc::io::WriteMysqlExt;
use crate::Column;

/// Implementors of this trait can be sent as a single resultset value to a MySQL/MariaDB client.
pub trait ToMysqlValue {
    /// Encode value using the text-based protocol.
    fn to_mysql_text<W: Write>(&self, w: &mut W) -> io::Result<()>;

    /// Encode value using the binary protocol.
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()>;

    /// Is this value NULL?
    fn is_null(&self) -> bool {
        false
    }
}

/// A value produced by a text-oriented execution engine that must be encoded according to the
/// MySQL column descriptor when a binary-protocol resultset is requested.
pub struct MySqlTextValue<'a>(pub &'a [u8]);

impl ToMysqlValue for MySqlTextValue<'_> {
    fn to_mysql_text<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.0.to_mysql_text(w)
    }

    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        if !matches!(
            c.coltype,
            ColumnType::MYSQL_TYPE_TINY
                | ColumnType::MYSQL_TYPE_SHORT
                | ColumnType::MYSQL_TYPE_YEAR
                | ColumnType::MYSQL_TYPE_LONG
                | ColumnType::MYSQL_TYPE_INT24
                | ColumnType::MYSQL_TYPE_LONGLONG
                | ColumnType::MYSQL_TYPE_FLOAT
                | ColumnType::MYSQL_TYPE_DOUBLE
                | ColumnType::MYSQL_TYPE_DATE
                | ColumnType::MYSQL_TYPE_DATETIME
                | ColumnType::MYSQL_TYPE_TIMESTAMP
                | ColumnType::MYSQL_TYPE_TIME
        ) {
            // Character and binary result fields carry bytes in the session's
            // result character set. They need not be UTF-8 (for example
            // koi8r/cp1251), so preserve them byte-for-byte in binary rows.
            return self.0.to_mysql_bin(w, c);
        }
        let text = std::str::from_utf8(self.0)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let unsigned = c.colflags.contains(ColumnFlags::UNSIGNED_FLAG);
        match c.coltype {
            ColumnType::MYSQL_TYPE_TINY => {
                if text.eq_ignore_ascii_case("true") {
                    return 1_i8.to_mysql_bin(w, c);
                }
                if text.eq_ignore_ascii_case("false") {
                    return 0_i8.to_mysql_bin(w, c);
                }
                if unsigned {
                    text.parse::<u8>().map_err(io_invalid)?.to_mysql_bin(w, c)
                } else {
                    text.parse::<i8>().map_err(io_invalid)?.to_mysql_bin(w, c)
                }
            }
            ColumnType::MYSQL_TYPE_SHORT | ColumnType::MYSQL_TYPE_YEAR => {
                if unsigned {
                    text.parse::<u16>().map_err(io_invalid)?.to_mysql_bin(w, c)
                } else {
                    text.parse::<i16>().map_err(io_invalid)?.to_mysql_bin(w, c)
                }
            }
            ColumnType::MYSQL_TYPE_LONG | ColumnType::MYSQL_TYPE_INT24 => {
                if unsigned {
                    text.parse::<u32>().map_err(io_invalid)?.to_mysql_bin(w, c)
                } else {
                    text.parse::<i32>().map_err(io_invalid)?.to_mysql_bin(w, c)
                }
            }
            ColumnType::MYSQL_TYPE_LONGLONG => {
                if unsigned {
                    text.parse::<u64>().map_err(io_invalid)?.to_mysql_bin(w, c)
                } else {
                    text.parse::<i64>().map_err(io_invalid)?.to_mysql_bin(w, c)
                }
            }
            ColumnType::MYSQL_TYPE_FLOAT => {
                text.parse::<f32>().map_err(io_invalid)?.to_mysql_bin(w, c)
            }
            ColumnType::MYSQL_TYPE_DOUBLE => {
                text.parse::<f64>().map_err(io_invalid)?.to_mysql_bin(w, c)
            }
            ColumnType::MYSQL_TYPE_DATE => write_mysql_text_date(w, text),
            ColumnType::MYSQL_TYPE_DATETIME | ColumnType::MYSQL_TYPE_TIMESTAMP => {
                write_mysql_text_datetime(w, text)
            }
            ColumnType::MYSQL_TYPE_TIME => write_mysql_text_time(w, text),
            _ => self.0.to_mysql_bin(w, c),
        }
    }
}

fn write_mysql_text_date<W: Write>(w: &mut W, text: &str) -> io::Result<()> {
    let (year, month, day) = mysql_text_date_parts(text)?;
    if year == 0 && month == 0 && day == 0 {
        return w.write_u8(0);
    }
    w.write_u8(4)?;
    w.write_u16::<LittleEndian>(year)?;
    w.write_u8(month)?;
    w.write_u8(day)
}

fn write_mysql_text_datetime<W: Write>(w: &mut W, text: &str) -> io::Result<()> {
    let (date, time) = text
        .split_once(' ')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid MySQL datetime"))?;
    let (year, month, day) = mysql_text_date_parts(date)?;
    let (negative, days, hour, minute, second, micros) = mysql_text_time_parts(time)?;
    if negative || days != 0 {
        return Err(io_invalid("invalid MySQL datetime clock"));
    }
    if year == 0 && month == 0 && day == 0 && hour == 0 && minute == 0 && second == 0 && micros == 0
    {
        return w.write_u8(0);
    }
    let length = if micros != 0 {
        11
    } else if hour != 0 || minute != 0 || second != 0 {
        7
    } else {
        4
    };
    w.write_u8(length)?;
    w.write_u16::<LittleEndian>(year)?;
    w.write_u8(month)?;
    w.write_u8(day)?;
    if length == 4 {
        return Ok(());
    }
    w.write_u8(hour)?;
    w.write_u8(minute)?;
    w.write_u8(second)?;
    if micros != 0 {
        w.write_u32::<LittleEndian>(micros)?;
    }
    Ok(())
}

fn write_mysql_text_time<W: Write>(w: &mut W, text: &str) -> io::Result<()> {
    let (negative, days, hour, minute, second, micros) = mysql_text_time_parts(text)?;
    if days == 0 && hour == 0 && minute == 0 && second == 0 && micros == 0 {
        return w.write_u8(0);
    }
    w.write_u8(if micros == 0 { 8 } else { 12 })?;
    w.write_u8(u8::from(negative))?;
    w.write_u32::<LittleEndian>(days)?;
    w.write_u8(hour)?;
    w.write_u8(minute)?;
    w.write_u8(second)?;
    if micros != 0 {
        w.write_u32::<LittleEndian>(micros)?;
    }
    Ok(())
}

fn mysql_text_date_parts(text: &str) -> io::Result<(u16, u8, u8)> {
    let mut parts = text.split('-');
    let (Some(year), Some(month), Some(day), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid MySQL date",
        ));
    };
    let (year, month, day) = (
        year.parse::<u16>().map_err(io_invalid)?,
        month.parse::<u8>().map_err(io_invalid)?,
        day.parse::<u8>().map_err(io_invalid)?,
    );
    // This is an output getter, not Field::store's calendar validator.
    // Native temporal Items can expose ALLOW_INVALID_DATES day 32..99;
    // Protocol_binary writes those actual components without revalidation.
    if year > 9999 || month > 12 || day > 99 {
        return Err(io_invalid("invalid MySQL date"));
    }
    Ok((year, month, day))
}

fn mysql_text_time_parts(text: &str) -> io::Result<(bool, u32, u8, u8, u8, u32)> {
    let (negative, text) = text
        .strip_prefix('-')
        .map(|text| (true, text))
        .unwrap_or((false, text));
    let (clock, fraction) = text.split_once('.').unwrap_or((text, ""));
    let mut parts = clock.split(':');
    let (Some(hour), Some(minute), Some(second), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid MySQL time",
        ));
    };
    let total_hours = hour.parse::<u32>().map_err(io_invalid)?;
    let minute = minute.parse::<u8>().map_err(io_invalid)?;
    let second = second.parse::<u8>().map_err(io_invalid)?;
    // Actual temporal Item output may contain STR_TO_DATE's day*24 hours.
    // Stored/parameter TIME range validation is a separate Field policy.
    if total_hours > 2399
        || minute > 59
        || second > 59
        || fraction.len() > 6
        || (text.contains('.') && fraction.is_empty())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid MySQL time",
        ));
    }
    let mut micros_text = fraction.to_string();
    while micros_text.len() < 6 {
        micros_text.push('0');
    }
    let micros = if micros_text.is_empty() {
        0
    } else {
        micros_text.parse::<u32>().map_err(io_invalid)?
    };
    Ok((
        negative,
        total_hours / 24,
        (total_hours % 24) as u8,
        minute,
        second,
        micros,
    ))
}

fn io_invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

macro_rules! mysql_text_trivial {
    () => {
        fn to_mysql_text<W: Write>(&self, w: &mut W) -> io::Result<()> {
            w.write_lenenc_str(format!("{}", self).as_bytes())
                .map(|_| ())
        }
    };
}

use std::fmt;
fn bad<V: fmt::Debug>(v: V, c: &Column) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("tried to use {:?} as {:?}", v, c.coltype),
    )
}

impl<T> ToMysqlValue for Option<T>
where
    T: ToMysqlValue,
{
    fn to_mysql_text<W: Write>(&self, w: &mut W) -> io::Result<()> {
        if let Some(ref v) = *self {
            v.to_mysql_text(w)
        } else {
            w.write_u8(0xFB)
        }
    }

    fn to_mysql_bin<W: Write>(&self, w: &mut W, ct: &Column) -> io::Result<()> {
        if let Some(ref v) = *self {
            v.to_mysql_bin(w, ct)
        } else {
            // should be handled by NULL map
            unreachable!();
        }
    }

    fn is_null(&self) -> bool {
        self.is_none()
    }
}

// NOTE: these rules can all go away when TryFrom stabilizes
//       see https://github.com/jonhoo/msql-srv/commit/13e5e753e5042a42cc45ad57c2b760561da2fb50
// NOTE: yes, I know the = / => distinction is ugly
macro_rules! like_try_into {
    ($self:ident, $source:ty = $target:ty, $w:ident, $m:ident, $c:ident) => {{
        let min = <$target>::MIN as $source;
        let max = <$target>::MAX as $source;
        if *$self <= max && *$self >= min {
            $w.$m(*$self as $target)
        } else {
            Err(bad($self, $c))
        }
    }};
    ($self:ident, $source:ty => $target:ty, $w:ident, $m:ident, $c:ident) => {{
        let min = <$target>::MIN as $source;
        let max = <$target>::MAX as $source;
        if *$self <= max && *$self >= min {
            $w.$m::<LittleEndian>(*$self as $target)
        } else {
            Err(bad($self, $c))
        }
    }};
}

macro_rules! forgiving_numeric {
    ($t:ty) => {
        impl ToMysqlValue for $t {
            mysql_text_trivial!();
            fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
                let signed = !c.colflags.contains(ColumnFlags::UNSIGNED_FLAG);
                match c.coltype {
                    ColumnType::MYSQL_TYPE_LONGLONG => {
                        if signed {
                            like_try_into!(self, $t => i64, w, write_i64, c)
                        } else {
                            like_try_into!(self, $t => u64, w, write_u64, c)
                        }
                    }
                    ColumnType::MYSQL_TYPE_LONG | ColumnType::MYSQL_TYPE_INT24 => {
                        if signed {
                            like_try_into!(self, $t => i32, w, write_i32, c)
                        } else {
                            like_try_into!(self, $t => u32, w, write_u32, c)
                        }
                    }
                    ColumnType::MYSQL_TYPE_SHORT | ColumnType::MYSQL_TYPE_YEAR => {
                        if signed {
                            like_try_into!(self, $t => i16, w, write_i16, c)
                        } else {
                            like_try_into!(self, $t => u16, w, write_u16, c)
                        }
                    }
                    ColumnType::MYSQL_TYPE_TINY => {
                        if signed {
                            like_try_into!(self, $t = i8, w, write_i8, c)
                        } else {
                            like_try_into!(self, $t = u8, w, write_u8, c)
                        }
                    }
                    _ => Err(bad(self, c)),
                }
            }
        }
    };
}

forgiving_numeric!(usize);
forgiving_numeric!(isize);

impl ToMysqlValue for u8 {
    mysql_text_trivial!();
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        let signed = !c.colflags.contains(ColumnFlags::UNSIGNED_FLAG);
        match c.coltype {
            ColumnType::MYSQL_TYPE_LONGLONG => {
                if signed {
                    w.write_i64::<LittleEndian>(i64::from(*self))
                } else {
                    w.write_u64::<LittleEndian>(u64::from(*self))
                }
            }
            ColumnType::MYSQL_TYPE_LONG | ColumnType::MYSQL_TYPE_INT24 => {
                if signed {
                    w.write_i32::<LittleEndian>(i32::from(*self))
                } else {
                    w.write_u32::<LittleEndian>(u32::from(*self))
                }
            }
            ColumnType::MYSQL_TYPE_SHORT | ColumnType::MYSQL_TYPE_YEAR => {
                if signed {
                    w.write_i16::<LittleEndian>(i16::from(*self))
                } else {
                    w.write_u16::<LittleEndian>(u16::from(*self))
                }
            }
            ColumnType::MYSQL_TYPE_TINY => {
                assert!(!signed);
                w.write_u8(*self)
            }
            _ => Err(bad(self, c)),
        }
    }
}

impl ToMysqlValue for i8 {
    mysql_text_trivial!();
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        let signed = !c.colflags.contains(ColumnFlags::UNSIGNED_FLAG);
        match c.coltype {
            ColumnType::MYSQL_TYPE_LONGLONG => {
                if signed {
                    w.write_i64::<LittleEndian>(i64::from(*self))
                } else {
                    w.write_u64::<LittleEndian>(*self as u64)
                }
            }
            ColumnType::MYSQL_TYPE_LONG | ColumnType::MYSQL_TYPE_INT24 => {
                if signed {
                    w.write_i32::<LittleEndian>(i32::from(*self))
                } else {
                    w.write_u32::<LittleEndian>(*self as u32)
                }
            }
            ColumnType::MYSQL_TYPE_SHORT | ColumnType::MYSQL_TYPE_YEAR => {
                if signed {
                    w.write_i16::<LittleEndian>(i16::from(*self))
                } else {
                    w.write_u16::<LittleEndian>(*self as u16)
                }
            }
            ColumnType::MYSQL_TYPE_TINY => {
                assert!(signed);
                w.write_i8(*self)
            }
            _ => Err(bad(self, c)),
        }
    }
}

impl ToMysqlValue for u16 {
    mysql_text_trivial!();
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        let signed = !c.colflags.contains(ColumnFlags::UNSIGNED_FLAG);
        match c.coltype {
            ColumnType::MYSQL_TYPE_LONGLONG => {
                if signed {
                    w.write_i64::<LittleEndian>(i64::from(*self))
                } else {
                    w.write_u64::<LittleEndian>(u64::from(*self))
                }
            }
            ColumnType::MYSQL_TYPE_LONG | ColumnType::MYSQL_TYPE_INT24 => {
                if signed {
                    w.write_i32::<LittleEndian>(i32::from(*self))
                } else {
                    w.write_u32::<LittleEndian>(u32::from(*self))
                }
            }
            ColumnType::MYSQL_TYPE_SHORT | ColumnType::MYSQL_TYPE_YEAR => {
                assert!(!signed);
                w.write_u16::<LittleEndian>(*self)
            }
            _ => Err(bad(self, c)),
        }
    }
}

impl ToMysqlValue for i16 {
    mysql_text_trivial!();
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        let signed = !c.colflags.contains(ColumnFlags::UNSIGNED_FLAG);
        match c.coltype {
            ColumnType::MYSQL_TYPE_LONGLONG => {
                if signed {
                    w.write_i64::<LittleEndian>(i64::from(*self))
                } else {
                    w.write_u64::<LittleEndian>(*self as u64)
                }
            }
            ColumnType::MYSQL_TYPE_LONG | ColumnType::MYSQL_TYPE_INT24 => {
                if signed {
                    w.write_i32::<LittleEndian>(i32::from(*self))
                } else {
                    w.write_u32::<LittleEndian>(*self as u32)
                }
            }
            ColumnType::MYSQL_TYPE_SHORT | ColumnType::MYSQL_TYPE_YEAR => {
                assert!(signed);
                w.write_i16::<LittleEndian>(*self)
            }
            _ => Err(bad(self, c)),
        }
    }
}

impl ToMysqlValue for u32 {
    mysql_text_trivial!();
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        let signed = !c.colflags.contains(ColumnFlags::UNSIGNED_FLAG);
        match c.coltype {
            ColumnType::MYSQL_TYPE_LONGLONG => {
                if signed {
                    w.write_i64::<LittleEndian>(i64::from(*self))
                } else {
                    w.write_u64::<LittleEndian>(u64::from(*self))
                }
            }
            ColumnType::MYSQL_TYPE_LONG | ColumnType::MYSQL_TYPE_INT24 => {
                assert!(!signed);
                w.write_u32::<LittleEndian>(*self)
            }
            _ => Err(bad(self, c)),
        }
    }
}

impl ToMysqlValue for i32 {
    mysql_text_trivial!();
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        let signed = !c.colflags.contains(ColumnFlags::UNSIGNED_FLAG);
        match c.coltype {
            ColumnType::MYSQL_TYPE_LONGLONG => {
                if signed {
                    w.write_i64::<LittleEndian>(i64::from(*self))
                } else {
                    w.write_u64::<LittleEndian>(*self as u64)
                }
            }
            ColumnType::MYSQL_TYPE_LONG | ColumnType::MYSQL_TYPE_INT24 => {
                assert!(signed);
                w.write_i32::<LittleEndian>(*self)
            }
            _ => Err(bad(self, c)),
        }
    }
}

impl ToMysqlValue for u64 {
    mysql_text_trivial!();
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        let signed = !c.colflags.contains(ColumnFlags::UNSIGNED_FLAG);
        match c.coltype {
            ColumnType::MYSQL_TYPE_LONGLONG => {
                assert!(!signed);
                w.write_u64::<LittleEndian>(*self)
            }
            _ => Err(bad(self, c)),
        }
    }
}

impl ToMysqlValue for i64 {
    mysql_text_trivial!();
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        let signed = !c.colflags.contains(ColumnFlags::UNSIGNED_FLAG);
        match c.coltype {
            ColumnType::MYSQL_TYPE_LONGLONG => {
                assert!(signed);
                w.write_i64::<LittleEndian>(*self)
            }
            _ => Err(bad(self, c)),
        }
    }
}

impl ToMysqlValue for f32 {
    mysql_text_trivial!();
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        match c.coltype {
            ColumnType::MYSQL_TYPE_DOUBLE => w.write_f64::<LittleEndian>(f64::from(*self)),
            ColumnType::MYSQL_TYPE_FLOAT => w.write_f32::<LittleEndian>(*self),
            _ => Err(bad(self, c)),
        }
    }
}

impl ToMysqlValue for f64 {
    mysql_text_trivial!();
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        match c.coltype {
            ColumnType::MYSQL_TYPE_DOUBLE => w.write_f64::<LittleEndian>(*self),
            _ => Err(bad(self, c)),
        }
    }
}

impl ToMysqlValue for String {
    fn to_mysql_text<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.as_bytes().to_mysql_text(w)
    }
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        self.as_bytes().to_mysql_bin(w, c)
    }
}

impl ToMysqlValue for str {
    fn to_mysql_text<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.as_bytes().to_mysql_text(w)
    }
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        self.as_bytes().to_mysql_bin(w, c)
    }
}

impl ToMysqlValue for [u8] {
    fn to_mysql_text<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_lenenc_str(self).map(|_| ())
    }
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        match c.coltype {
            ColumnType::MYSQL_TYPE_STRING
            | ColumnType::MYSQL_TYPE_VAR_STRING
            | ColumnType::MYSQL_TYPE_BLOB
            | ColumnType::MYSQL_TYPE_TINY_BLOB
            | ColumnType::MYSQL_TYPE_MEDIUM_BLOB
            | ColumnType::MYSQL_TYPE_LONG_BLOB
            | ColumnType::MYSQL_TYPE_SET
            | ColumnType::MYSQL_TYPE_ENUM
            | ColumnType::MYSQL_TYPE_DECIMAL
            | ColumnType::MYSQL_TYPE_VARCHAR
            | ColumnType::MYSQL_TYPE_BIT
            | ColumnType::MYSQL_TYPE_NEWDECIMAL
            | ColumnType::MYSQL_TYPE_GEOMETRY
            | ColumnType::MYSQL_TYPE_JSON => w.write_lenenc_str(self).map(|_| ()),
            _ => Err(bad(self, c)),
        }
    }
}

impl ToMysqlValue for Vec<u8> {
    fn to_mysql_text<W: Write>(&self, w: &mut W) -> io::Result<()> {
        (self[..]).to_mysql_text(w)
    }
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        (self[..]).to_mysql_bin(w, c)
    }
}

impl<T> ToMysqlValue for &T
where
    T: ToMysqlValue + ?Sized,
{
    fn to_mysql_text<W: Write>(&self, w: &mut W) -> io::Result<()> {
        (*self).to_mysql_text(w)
    }
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        (*self).to_mysql_bin(w, c)
    }
}

use chrono::{self, Datelike, NaiveDate, NaiveDateTime, Timelike};
impl ToMysqlValue for NaiveDate {
    fn to_mysql_text<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_lenenc_str(
            format!("{:04}-{:02}-{:02}", self.year(), self.month(), self.day()).as_bytes(),
        )
        .map(|_| ())
    }
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        match c.coltype {
            ColumnType::MYSQL_TYPE_DATE => {
                w.write_u8(4u8)?;
                w.write_u16::<LittleEndian>(self.year() as u16)?;
                w.write_u8(self.month() as u8)?;
                w.write_u8(self.day() as u8)
            }
            _ => Err(bad(self, c)),
        }
    }
}

impl ToMysqlValue for NaiveDateTime {
    fn to_mysql_text<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let us = self.nanosecond() / 1_000;

        if us != 0 {
            w.write_lenenc_str(
                format!(
                    "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}",
                    self.year(),
                    self.month(),
                    self.day(),
                    self.hour(),
                    self.minute(),
                    self.second(),
                    us
                )
                .as_bytes(),
            )
            .map(|_| ())
        } else {
            w.write_lenenc_str(
                format!(
                    "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                    self.year(),
                    self.month(),
                    self.day(),
                    self.hour(),
                    self.minute(),
                    self.second()
                )
                .as_bytes(),
            )
            .map(|_| ())
        }
    }
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        match c.coltype {
            ColumnType::MYSQL_TYPE_DATETIME | ColumnType::MYSQL_TYPE_TIMESTAMP => {
                let us = self.nanosecond() / 1_000;

                if us != 0 {
                    w.write_u8(11u8)?;
                } else {
                    w.write_u8(7u8)?;
                }
                w.write_u16::<LittleEndian>(self.year() as u16)?;
                w.write_u8(self.month() as u8)?;
                w.write_u8(self.day() as u8)?;
                w.write_u8(self.hour() as u8)?;
                w.write_u8(self.minute() as u8)?;
                w.write_u8(self.second() as u8)?;

                if us != 0 {
                    w.write_u32::<LittleEndian>(us)?;
                }
                Ok(())
            }
            _ => Err(bad(self, c)),
        }
    }
}

use std::time::Duration;
impl ToMysqlValue for Duration {
    fn to_mysql_text<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let s = self.as_secs();
        //let d = s / (24 * 3600);
        // assert!(d <= 34);
        //let h = (s % (24 * 3600)) / 3600;
        let h = s / 3600;
        let m = (s % 3600) / 60;
        let s = s % 60;
        let us = self.subsec_micros();
        if us != 0 {
            w.write_lenenc_str(format!("{h:02}:{m:02}:{s:02}.{us:06}").as_bytes())
                .map(|_| ())
        } else {
            w.write_lenenc_str(format!("{h:02}:{m:02}:{s:02}").as_bytes())
                .map(|_| ())
        }
    }

    #[allow(clippy::many_single_char_names)]
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        let s = self.as_secs();
        let d = s / (24 * 3600);
        assert!(d <= 34);
        let h = (s % (24 * 3600)) / 3600;
        let m = (s % 3600) / 60;
        let s = s % 60;
        let us = self.subsec_micros();

        match c.coltype {
            ColumnType::MYSQL_TYPE_TIME => {
                if self.as_secs() == 0 && us == 0 {
                    w.write_u8(0u8)?;
                } else {
                    if us != 0 {
                        w.write_u8(12u8)?;
                    } else {
                        w.write_u8(8u8)?;
                    }

                    w.write_u8(0u8)?; // positive only (for now)
                    w.write_u32::<LittleEndian>(d as u32)?;
                    w.write_u8(h as u8)?;
                    w.write_u8(m as u8)?;
                    w.write_u8(s as u8)?;

                    if us != 0 {
                        w.write_u32::<LittleEndian>(us)?;
                    }
                }
                Ok(())
            }
            _ => Err(bad(self, c)),
        }
    }
}

impl ToMysqlValue for myc::value::Value {
    #[allow(clippy::many_single_char_names)]
    fn to_mysql_text<W: Write>(&self, w: &mut W) -> io::Result<()> {
        match *self {
            myc::value::Value::NULL => None::<u8>.to_mysql_text(w),
            myc::value::Value::Bytes(ref bytes) => bytes.to_mysql_text(w),
            myc::value::Value::Int(n) => n.to_mysql_text(w),
            myc::value::Value::UInt(n) => n.to_mysql_text(w),
            myc::value::Value::Float(f) => f.to_mysql_text(w),
            myc::value::Value::Double(f) => f.to_mysql_text(w),
            myc::value::Value::Date(y, mo, d, h, mi, s, us) => {
                NaiveDate::from_ymd_opt(i32::from(y), u32::from(mo), u32::from(d))
                    .unwrap()
                    .and_hms_micro_opt(u32::from(h), u32::from(mi), u32::from(s), us)
                    .unwrap()
                    .to_mysql_text(w)
            }
            myc::value::Value::Time(neg, d, h, m, s, us) => {
                if neg {
                    return Err(io::Error::other("negative times not yet supported"));
                }
                (chrono::Duration::days(i64::from(d))
                    + chrono::Duration::hours(i64::from(h))
                    + chrono::Duration::minutes(i64::from(m))
                    + chrono::Duration::seconds(i64::from(s))
                    + chrono::Duration::microseconds(i64::from(us)))
                .to_std()
                .expect("only positive times at the moment")
                .to_mysql_text(w)
            }
        }
    }

    #[allow(clippy::many_single_char_names)]
    fn to_mysql_bin<W: Write>(&self, w: &mut W, c: &Column) -> io::Result<()> {
        match *self {
            myc::value::Value::NULL => unreachable!(),
            myc::value::Value::Bytes(ref bytes) => bytes.to_mysql_bin(w, c),
            myc::value::Value::Int(n) => {
                // we *could* just delegate to i64 impl here, but then you couldn't use myc::value::Value
                // and return, say, a short. also, myc uses i64 for *every* number type, *except*
                // u64, so we even need to coerce across unsigned :( the good news is that our
                // impls for numbers auto-upgrade to wider coltypes, so we can just downcast to the
                // smallest containing type, and then call on that
                let signed = !c.colflags.contains(ColumnFlags::UNSIGNED_FLAG);
                if signed {
                    if n >= i64::from(i8::MIN) && n <= i64::from(i8::MAX) {
                        (n as i8).to_mysql_bin(w, c)
                    } else if n >= i64::from(i16::MIN) && n <= i64::from(i16::MAX) {
                        (n as i16).to_mysql_bin(w, c)
                    } else if n >= i64::from(i32::MIN) && n <= i64::from(i32::MAX) {
                        (n as i32).to_mysql_bin(w, c)
                    } else {
                        n.to_mysql_bin(w, c)
                    }
                } else if n < 0 {
                    Err(bad(self, c))
                } else if n <= i64::from(u8::MAX) {
                    (n as u8).to_mysql_bin(w, c)
                } else if n <= i64::from(u16::MAX) {
                    (n as u16).to_mysql_bin(w, c)
                } else if n <= i64::from(u32::MAX) {
                    (n as u32).to_mysql_bin(w, c)
                } else {
                    // must work since u64::MAX > i64::MAX, and n >= 0
                    (n as u64).to_mysql_bin(w, c)
                }
            }
            myc::value::Value::UInt(n) => {
                // we are not as lenient with unsigned ints because the mysql crate isn't either
                n.to_mysql_bin(w, c)
            }
            myc::value::Value::Float(f) => f.to_mysql_bin(w, c),
            myc::value::Value::Double(f) => f.to_mysql_bin(w, c),
            myc::value::Value::Date(y, mo, d, h, mi, s, us) => {
                NaiveDate::from_ymd_opt(i32::from(y), u32::from(mo), u32::from(d))
                    .unwrap()
                    .and_hms_micro_opt(u32::from(h), u32::from(mi), u32::from(s), us)
                    .unwrap()
                    .to_mysql_bin(w, c)
            }
            myc::value::Value::Time(neg, d, h, m, s, us) => {
                if neg {
                    return Err(io::Error::other("negative times not yet supported"));
                }
                (chrono::Duration::days(i64::from(d))
                    + chrono::Duration::hours(i64::from(h))
                    + chrono::Duration::minutes(i64::from(m))
                    + chrono::Duration::seconds(i64::from(s))
                    + chrono::Duration::microseconds(i64::from(us)))
                .to_std()
                .expect("only positive times at the moment")
                .to_mysql_bin(w, c)
            }
        }
    }

    fn is_null(&self) -> bool {
        matches!(*self, myc::value::Value::NULL)
    }
}
