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

use byteorder::{LittleEndian, ReadBytesExt};

use crate::myc::constants::ColumnType;

/// MySQL value as provided when executing prepared statements.
#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Value<'a>(ValueInner<'a>);

/// A representation of a concrete, typed MySQL value.
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ValueInner<'a> {
    /// The MySQL `NULL` value.
    NULL,
    /// An untyped sequence of bytes (usually a text type or `MYSQL_TYPE_BLOB`).
    Bytes(&'a [u8]),
    /// A signed integer.
    Int(i64),
    /// An unsigned integer.
    UInt(u64),
    /// A four-byte floating point parameter, before backend Item promotion.
    Float(f32),
    /// An eight-byte floating point parameter.
    Double(f64),
    /// A [binary encoding](https://mariadb.com/kb/en/library/resultset-row/#date-binary-encoding)
    /// of a `MYSQL_TYPE_DATE`.
    Date(&'a [u8]),
    /// A [binary encoding](https://mariadb.com/kb/en/library/resultset-row/#time-binary-encoding)
    /// of a `MYSQL_TYPE_TIME`.
    Time(&'a [u8]),
    /// A [binary
    /// encoding](https://mariadb.com/kb/en/library/resultset-row/#timestamp-binary-encoding) of a
    /// `MYSQL_TYPE_TIMESTAMP` or `MYSQL_TYPE_DATETIME`.
    Datetime(&'a [u8]),
}

impl<'a> Value<'a> {
    /// Return the inner stored representation of this value.
    ///
    /// This may be useful for when you do not care about the exact data type used for a column,
    /// but instead wish to introspect a value you are given at runtime. Note that the contained
    /// value may be stored in a type that is more general than what the corresponding parameter
    /// type allows (e.g., a `u8` will be stored as an `u64`).
    pub fn into_inner(self) -> ValueInner<'a> {
        self.0
    }

    pub(crate) fn null() -> Self {
        Value(ValueInner::NULL)
    }

    /// Returns true if this is a NULL value
    pub fn is_null(&self) -> bool {
        matches!(self.0, ValueInner::NULL)
    }

    pub(crate) fn bytes(input: &'a [u8]) -> Value<'a> {
        Value(ValueInner::Bytes(input))
    }

    /// Converts an already framed placeholder payload, without rebuilding a
    /// length prefix or reparsing a rendered value. Framing belongs to params.
    pub(crate) fn from_parameter_payload(
        mut input: &'a [u8],
        ct: ColumnType,
        unsigned: bool,
    ) -> io::Result<Self> {
        let wrong_length = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid parameter payload length",
            )
        };
        let value = match ct {
            ColumnType::MYSQL_TYPE_TINY => {
                if input.len() != 1 {
                    return Err(wrong_length());
                }
                if unsigned {
                    ValueInner::UInt(u64::from(input.read_u8()?))
                } else {
                    ValueInner::Int(i64::from(input.read_i8()?))
                }
            }
            ColumnType::MYSQL_TYPE_SHORT => {
                if input.len() != 2 {
                    return Err(wrong_length());
                }
                if unsigned {
                    ValueInner::UInt(u64::from(input.read_u16::<LittleEndian>()?))
                } else {
                    ValueInner::Int(i64::from(input.read_i16::<LittleEndian>()?))
                }
            }
            ColumnType::MYSQL_TYPE_LONG | ColumnType::MYSQL_TYPE_INT24 => {
                if input.len() != 4 {
                    return Err(wrong_length());
                }
                if unsigned {
                    ValueInner::UInt(u64::from(input.read_u32::<LittleEndian>()?))
                } else {
                    ValueInner::Int(i64::from(input.read_i32::<LittleEndian>()?))
                }
            }
            ColumnType::MYSQL_TYPE_LONGLONG => {
                if input.len() != 8 {
                    return Err(wrong_length());
                }
                if unsigned {
                    ValueInner::UInt(input.read_u64::<LittleEndian>()?)
                } else {
                    ValueInner::Int(input.read_i64::<LittleEndian>()?)
                }
            }
            ColumnType::MYSQL_TYPE_FLOAT => {
                if input.len() != 4 {
                    return Err(wrong_length());
                }
                ValueInner::Float(input.read_f32::<LittleEndian>()?)
            }
            ColumnType::MYSQL_TYPE_DOUBLE => {
                if input.len() != 8 {
                    return Err(wrong_length());
                }
                ValueInner::Double(input.read_f64::<LittleEndian>()?)
            }
            ColumnType::MYSQL_TYPE_DATE => {
                ValueInner::Date(if input.len() < 4 { &[] } else { &input[..4] })
            }
            ColumnType::MYSQL_TYPE_TIME => {
                if (9..12).contains(&input.len()) {
                    return Err(wrong_length());
                }
                ValueInner::Time(if input.len() < 8 {
                    &[]
                } else if input.len() == 8 {
                    input
                } else {
                    &input[..12]
                })
            }
            ColumnType::MYSQL_TYPE_DATETIME | ColumnType::MYSQL_TYPE_TIMESTAMP => {
                if !matches!(input.len(), 0 | 4 | 7 | 11 | 13) {
                    return Err(wrong_length());
                }
                ValueInner::Datetime(input)
            }
            ColumnType::MYSQL_TYPE_NULL => ValueInner::NULL,
            _ => ValueInner::Bytes(input),
        };
        Ok(Value(value))
    }
}

// NOTE: these should all be TryFrom
macro_rules! impl_into {
    ($t:ty, $($variant:path),*) => {
        impl<'a> From<Value<'a>> for $t {
            fn from(val: Value<'a>) -> Self {
                match val.0 {
                    $($variant(v) => v as $t),*,
                    v => panic!(concat!("invalid type conversion from {:?} to ", stringify!($t)), v)
                }
            }
        }
    }
}

impl_into!(u8, ValueInner::UInt, ValueInner::Int);
impl_into!(u16, ValueInner::UInt, ValueInner::Int);
impl_into!(u32, ValueInner::UInt, ValueInner::Int);
impl_into!(u64, ValueInner::UInt);
impl_into!(i8, ValueInner::UInt, ValueInner::Int);
impl_into!(i16, ValueInner::UInt, ValueInner::Int);
impl_into!(i32, ValueInner::UInt, ValueInner::Int);
impl_into!(i64, ValueInner::Int);
impl_into!(f32, ValueInner::Float, ValueInner::Double);
impl_into!(f64, ValueInner::Float, ValueInner::Double);
impl_into!(&'a [u8], ValueInner::Bytes);

impl<'a> From<Value<'a>> for &'a str {
    fn from(val: Value<'a>) -> Self {
        if let ValueInner::Bytes(v) = val.0 {
            ::std::str::from_utf8(v).unwrap()
        } else {
            panic!("invalid type conversion from {val:?} to string")
        }
    }
}

use chrono::{NaiveDate, NaiveDateTime};
impl<'a> From<Value<'a>> for NaiveDate {
    fn from(val: Value<'a>) -> Self {
        if let ValueInner::Date(mut v) = val.0 {
            assert_eq!(v.len(), 4);
            NaiveDate::from_ymd_opt(
                i32::from(v.read_u16::<LittleEndian>().unwrap()),
                u32::from(v.read_u8().unwrap()),
                u32::from(v.read_u8().unwrap()),
            )
            .unwrap()
        } else {
            panic!("invalid type conversion from {val:?} to date")
        }
    }
}

impl<'a> From<Value<'a>> for NaiveDateTime {
    fn from(val: Value<'a>) -> Self {
        to_naive_datetime(val).unwrap()
    }
}

pub fn to_naive_datetime(val: Value) -> Result<NaiveDateTime, io::Error> {
    let ValueInner::Datetime(v) = val.0 else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid type conversion from {val:?} to datetime"),
        ));
    };

    let len = v.len();

    let v = &mut io::Cursor::new(v);

    // unwrap safety: guarded by `v.len()` check
    fn read_ymd(v: &mut io::Cursor<&[u8]>) -> (i32, u32, u32) {
        let y = i32::from(v.read_u16::<LittleEndian>().unwrap());
        let m = u32::from(v.read_u8().unwrap());
        let d = u32::from(v.read_u8().unwrap());
        (y, m, d)
    }

    // unwrap safety: guarded by `v.len()` check
    fn read_hms(v: &mut io::Cursor<&[u8]>) -> (u32, u32, u32) {
        let h = u32::from(v.read_u8().unwrap());
        let m = u32::from(v.read_u8().unwrap());
        let s = u32::from(v.read_u8().unwrap());
        (h, m, s)
    }

    // Timestamp binary encoding:
    // https://mariadb.com/kb/en/resultset-row/#timestamp-binary-encoding
    let d = match len {
        0 => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "'0000-00-00 00:00:00' is a valid timestamp value but not representable by NaiveDateTime!",
            ));
        }
        4 => {
            let (y, m, d) = read_ymd(v);
            NaiveDate::from_ymd_opt(y, m, d).and_then(|x| x.and_hms_opt(0, 0, 0))
        }
        7 => {
            let (y, m, d) = read_ymd(v);
            NaiveDate::from_ymd_opt(y, m, d).and_then(|x| {
                let (h, m, s) = read_hms(v);
                x.and_hms_opt(h, m, s)
            })
        }
        11 => {
            let (y, m, d) = read_ymd(v);
            NaiveDate::from_ymd_opt(y, m, d).and_then(|x| {
                let (h, m, s) = read_hms(v);

                // unwrap safety: guarded by `v.len()` check
                let us = v.read_u32::<LittleEndian>().unwrap();

                x.and_hms_micro_opt(h, m, s, us)
            })
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("illegal timestamp value length: {len}"),
            ));
        }
    };

    d.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid data conversion from {val:?} to datetime"),
        )
    })
}

use std::time::Duration;

impl<'a> From<Value<'a>> for Duration {
    fn from(val: Value<'a>) -> Self {
        if let ValueInner::Time(mut v) = val.0 {
            assert!(v.is_empty() || v.len() == 8 || v.len() == 12);

            if v.is_empty() {
                return Duration::from_secs(0);
            }

            let neg = v.read_u8().unwrap();
            if neg != 0u8 {
                unimplemented!();
            }

            let days = u64::from(v.read_u32::<LittleEndian>().unwrap());
            let hours = u64::from(v.read_u8().unwrap());
            let minutes = u64::from(v.read_u8().unwrap());
            let seconds = u64::from(v.read_u8().unwrap());
            let micros = if v.len() == 12 {
                v.read_u32::<LittleEndian>().unwrap()
            } else {
                0
            };

            Duration::new(
                days * 86_400 + hours * 3_600 + minutes * 60 + seconds,
                micros * 1_000,
            )
        } else {
            panic!("invalid type conversion from {val:?} to datetime")
        }
    }
}
