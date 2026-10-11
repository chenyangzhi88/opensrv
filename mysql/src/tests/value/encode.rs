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

use crate::value::ToMysqlValue;
use crate::{Column, ColumnFlags, ColumnType};
use chrono::{self, TimeZone};
use std::time;

mod roundtrip_text {
    use super::*;

    use myc::{
        io::ParseBuf,
        proto::MyDeserialize,
        value::{convert::FromValue, TextValue, ValueDeserializer},
    };

    macro_rules! rt {
        ($name:ident, $t:ty, $v:expr) => {
            #[test]
            fn $name() {
                let mut data = Vec::new();
                let v: $t = $v;
                v.to_mysql_text(&mut data).unwrap();
                let mut pb = ParseBuf(&data[..]);
                assert_eq!(
                    <$t>::from_value(
                        ValueDeserializer::<TextValue>::deserialize((), &mut pb)
                            .unwrap()
                            .0,
                    ),
                    v
                );
            }
        };
    }

    rt!(u8_one, u8, 1);
    rt!(i8_one, i8, 1);
    rt!(u16_one, u16, 1);
    rt!(i16_one, i16, 1);
    rt!(u32_one, u32, 1);
    rt!(i32_one, i32, 1);
    rt!(u64_one, u64, 1);
    rt!(i64_one, i64, 1);
    rt!(f32_one, f32, 1.0);
    rt!(f64_one, f64, 1.0);

    rt!(u8_max, u8, u8::MAX);
    rt!(i8_max, i8, i8::MAX);
    rt!(u16_max, u16, u16::MAX);
    rt!(i16_max, i16, i16::MAX);
    rt!(u32_max, u32, u32::MAX);
    rt!(i32_max, i32, i32::MAX);
    rt!(u64_max, u64, u64::MAX);
    rt!(i64_max, i64, i64::MAX);

    rt!(opt_none, Option<u8>, None);
    rt!(opt_some, Option<u8>, Some(1));

    rt!(time, chrono::NaiveDate, chrono::Local::now().date_naive());
    rt!(
        datetime,
        chrono::NaiveDateTime,
        chrono::Utc
            .with_ymd_and_hms(1989, 12, 7, 8, 0, 4)
            .unwrap()
            .naive_utc()
    );
    rt!(dur, time::Duration, time::Duration::from_secs(1893));
    rt!(dur_micro, time::Duration, time::Duration::new(1893, 5000));
    rt!(dur_zero, time::Duration, time::Duration::from_secs(0));
    rt!(bytes, Vec<u8>, vec![0x42, 0x00, 0x1a]);
    rt!(string, String, "foobar".to_owned());
}

mod roundtrip_bin {
    use super::*;

    use myc::{
        io::ParseBuf,
        proto::MyDeserialize,
        value::{convert::FromValue, BinValue, ValueDeserializer},
    };

    macro_rules! rt {
        ($name:ident, $t:ty, $v:expr, $ct:expr) => {
            rt!($name, $t, $v, $ct, false);
        };
        ($name:ident, $t:ty, $v:expr, $ct:expr, $sig:expr) => {
            #[test]
            fn $name() {
                let mut data = Vec::new();
                let mut col = Column {
                    database: Vec::new(),
                    org_table: Vec::new(),
                    org_column: Vec::new(),
                    table: Vec::new(),
                    column: Vec::new(),
                    collen: 0,
                    charset: None,
                    coltype: $ct,
                    colflags: ColumnFlags::empty(),
                    decimals: None,
                };

                if !$sig {
                    col.colflags.insert(ColumnFlags::UNSIGNED_FLAG);
                }

                let v: $t = $v;
                v.to_mysql_bin(&mut data, &col).unwrap();
                let mut pb = ParseBuf(&data[..]);
                assert_eq!(
                    <$t>::from_value(
                        ValueDeserializer::<BinValue>::deserialize(
                            (
                                $ct,
                                if $sig {
                                    ColumnFlags::empty()
                                } else {
                                    ColumnFlags::UNSIGNED_FLAG
                                }
                            ),
                            &mut pb
                        )
                        .unwrap()
                        .0,
                    ),
                    v
                );
            }
        };
    }

    rt!(u8_one, u8, 1, ColumnType::MYSQL_TYPE_TINY, false);
    rt!(i8_one, i8, 1, ColumnType::MYSQL_TYPE_TINY, true);
    rt!(u8_one_short, u8, 1, ColumnType::MYSQL_TYPE_SHORT, false);
    rt!(i8_one_short, i8, 1, ColumnType::MYSQL_TYPE_SHORT, true);
    rt!(u8_one_long, u8, 1, ColumnType::MYSQL_TYPE_LONG, false);
    rt!(i8_one_long, i8, 1, ColumnType::MYSQL_TYPE_LONG, true);
    rt!(
        u8_one_longlong,
        u8,
        1,
        ColumnType::MYSQL_TYPE_LONGLONG,
        false
    );
    rt!(
        i8_one_longlong,
        i8,
        1,
        ColumnType::MYSQL_TYPE_LONGLONG,
        true
    );
    rt!(u16_one, u16, 1, ColumnType::MYSQL_TYPE_SHORT, false);
    rt!(i16_one, i16, 1, ColumnType::MYSQL_TYPE_SHORT, true);
    rt!(u16_one_long, u16, 1, ColumnType::MYSQL_TYPE_LONG, false);
    rt!(i16_one_long, i16, 1, ColumnType::MYSQL_TYPE_LONG, true);
    rt!(
        u16_one_longlong,
        u16,
        1,
        ColumnType::MYSQL_TYPE_LONGLONG,
        false
    );
    rt!(
        i16_one_longlong,
        i16,
        1,
        ColumnType::MYSQL_TYPE_LONGLONG,
        true
    );
    rt!(u32_one_long, u32, 1, ColumnType::MYSQL_TYPE_LONG, false);
    rt!(i32_one_long, i32, 1, ColumnType::MYSQL_TYPE_LONG, true);
    rt!(
        u32_one_longlong,
        u32,
        1,
        ColumnType::MYSQL_TYPE_LONGLONG,
        false
    );
    rt!(
        i32_one_longlong,
        i32,
        1,
        ColumnType::MYSQL_TYPE_LONGLONG,
        true
    );
    rt!(u64_one, u64, 1, ColumnType::MYSQL_TYPE_LONGLONG, false);
    rt!(i64_one, i64, 1, ColumnType::MYSQL_TYPE_LONGLONG, true);

    rt!(f32_one, f32, 1.0, ColumnType::MYSQL_TYPE_FLOAT, false);
    rt!(f64_one, f64, 1.0, ColumnType::MYSQL_TYPE_DOUBLE, false);

    rt!(u8_max, u8, u8::MAX, ColumnType::MYSQL_TYPE_TINY, false);
    rt!(i8_max, i8, i8::MAX, ColumnType::MYSQL_TYPE_TINY, true);
    rt!(u16_max, u16, u16::MAX, ColumnType::MYSQL_TYPE_SHORT, false);
    rt!(i16_max, i16, i16::MAX, ColumnType::MYSQL_TYPE_SHORT, true);
    rt!(u32_max, u32, u32::MAX, ColumnType::MYSQL_TYPE_LONG, false);
    rt!(i32_max, i32, i32::MAX, ColumnType::MYSQL_TYPE_LONG, true);
    rt!(
        u64_max,
        u64,
        u64::MAX,
        ColumnType::MYSQL_TYPE_LONGLONG,
        false
    );
    rt!(
        i64_max,
        i64,
        i64::MAX,
        ColumnType::MYSQL_TYPE_LONGLONG,
        true
    );

    rt!(opt_some, Option<u8>, Some(1), ColumnType::MYSQL_TYPE_TINY);

    rt!(
        time,
        chrono::NaiveDate,
        chrono::Local::now().date_naive(),
        ColumnType::MYSQL_TYPE_DATE
    );
    rt!(
        datetime,
        chrono::NaiveDateTime,
        chrono::Utc
            .with_ymd_and_hms(1989, 12, 7, 8, 0, 4)
            .unwrap()
            .naive_utc(),
        ColumnType::MYSQL_TYPE_DATETIME
    );
    rt!(
        dur,
        time::Duration,
        time::Duration::from_secs(1893),
        ColumnType::MYSQL_TYPE_TIME
    );
    rt!(
        bytes,
        Vec<u8>,
        vec![0x42, 0x00, 0x1a],
        ColumnType::MYSQL_TYPE_BLOB
    );
    rt!(
        string,
        String,
        "foobar".to_owned(),
        ColumnType::MYSQL_TYPE_STRING
    );
}

#[test]
fn mysql_text_temporals_use_binary_protocol_encoding() {
    let column = |coltype| Column {
        database: Vec::new(),
        org_table: Vec::new(),
        org_column: Vec::new(),
        table: Vec::new(),
        column: Vec::new(),
        collen: 0,
        charset: None,
        coltype,
        colflags: ColumnFlags::empty(),
        decimals: None,
    };

    let mut date = Vec::new();
    crate::MySqlTextValue(b"2002-01-02")
        .to_mysql_bin(&mut date, &column(ColumnType::MYSQL_TYPE_DATE))
        .unwrap();
    assert_eq!(date, vec![4, 0xd2, 0x07, 1, 2]);

    let mut zero_datetime = Vec::new();
    crate::MySqlTextValue(b"0000-00-00 00:00:00")
        .to_mysql_bin(&mut zero_datetime, &column(ColumnType::MYSQL_TYPE_DATETIME))
        .unwrap();
    assert_eq!(zero_datetime, vec![0]);

    let mut time = Vec::new();
    crate::MySqlTextValue(b"12:49:00")
        .to_mysql_bin(&mut time, &column(ColumnType::MYSQL_TYPE_TIME))
        .unwrap();
    assert_eq!(time, vec![8, 0, 0, 0, 0, 0, 12, 49, 0]);
}

#[test]
fn mysql_text_value_preserves_non_utf8_character_bytes() {
    let column = Column {
        database: Vec::new(),
        org_table: Vec::new(),
        org_column: Vec::new(),
        table: Vec::new(),
        column: Vec::new(),
        collen: 0,
        charset: None,
        coltype: ColumnType::MYSQL_TYPE_VAR_STRING,
        colflags: ColumnFlags::empty(),
        decimals: None,
    };
    let bytes = [0xee, 0xd5, 0x2c, 0x20];
    let mut encoded = Vec::new();
    crate::MySqlTextValue(&bytes)
        .to_mysql_bin(&mut encoded, &column)
        .unwrap();
    assert_eq!(encoded, vec![4, 0xee, 0xd5, 0x2c, 0x20]);
}

#[test]
fn stage2_temporal_codec_rejects_invalid_ranges_without_truncation() {
    for (coltype, values) in [
        (
            ColumnType::MYSQL_TYPE_TIME,
            vec!["2400:00:00", "12:00:00.1234567", "12:00:00.", "12:60:00"],
        ),
        (
            ColumnType::MYSQL_TYPE_DATE,
            vec!["10000-01-01", "2024-13-01", "2024-01-100"],
        ),
        (
            ColumnType::MYSQL_TYPE_DATETIME,
            vec![
                "2024-01-01 24:00:00",
                "2024-01-01 -01:00:00",
                "2024-01-100 00:00:00",
            ],
        ),
    ] {
        let column = Column {
            database: vec![],
            table: vec![],
            org_table: vec![],
            column: vec![],
            org_column: vec![],
            collen: 0,
            charset: Some(63),
            coltype,
            colflags: ColumnFlags::empty(),
            decimals: Some(6),
        };
        for value in values {
            assert!(
                crate::MySqlTextValue(value.as_bytes())
                    .to_mysql_bin(&mut Vec::new(), &column)
                    .is_err(),
                "{value}"
            );
        }
    }
}

#[test]
fn native_temporal_item_components_keep_binary_output_lengths_and_invalid_days() {
    // Fixed 8.0.46 Protocol_binary::{store_date,store_datetime}: calendar
    // components are output facts, not a second Gregorian Field-store check.
    let column = |coltype| Column {
        database: vec![],
        org_table: vec![],
        table: vec![],
        org_column: vec![],
        column: vec![],
        collen: 0,
        charset: Some(63),
        coltype,
        colflags: ColumnFlags::empty(),
        decimals: Some(6),
    };
    for (text, coltype, expected) in [
        ("0000-00-00", ColumnType::MYSQL_TYPE_DATE, vec![0]),
        (
            "2024-01-32",
            ColumnType::MYSQL_TYPE_DATE,
            vec![4, 0xe8, 0x07, 1, 32],
        ),
        (
            "9999-12-99",
            ColumnType::MYSQL_TYPE_DATE,
            vec![4, 0x0f, 0x27, 12, 99],
        ),
        (
            "0000-00-00 00:00:00",
            ColumnType::MYSQL_TYPE_DATETIME,
            vec![0],
        ),
        (
            "2024-01-32 00:00:00",
            ColumnType::MYSQL_TYPE_DATETIME,
            vec![4, 0xe8, 0x07, 1, 32],
        ),
        (
            "2024-01-32 00:00:01",
            ColumnType::MYSQL_TYPE_DATETIME,
            vec![7, 0xe8, 0x07, 1, 32, 0, 0, 1],
        ),
        (
            "9999-12-99 23:59:59.999999",
            ColumnType::MYSQL_TYPE_DATETIME,
            vec![11, 0x0f, 0x27, 12, 99, 23, 59, 59, 0x3f, 0x42, 0x0f, 0],
        ),
        (
            "2024-01-32 00:00:00.000001",
            ColumnType::MYSQL_TYPE_TIMESTAMP,
            vec![11, 0xe8, 0x07, 1, 32, 0, 0, 0, 1, 0, 0, 0],
        ),
    ] {
        let mut encoded = vec![];
        crate::MySqlTextValue(text.as_bytes())
            .to_mysql_bin(&mut encoded, &column(coltype))
            .unwrap();
        assert_eq!(encoded, expected, "{text}");
    }
}

#[test]
fn native_time_item_day_hours_are_not_clamped_by_the_output_codec() {
    let column = Column {
        database: vec![],
        org_table: vec![],
        table: vec![],
        org_column: vec![],
        column: vec![],
        collen: 17,
        charset: Some(63),
        coltype: ColumnType::MYSQL_TYPE_TIME,
        colflags: ColumnFlags::empty(),
        decimals: Some(6),
    };
    for (hours, days, hour) in [(838, 34, 22), (839, 34, 23), (2399, 99, 23)] {
        for (negative, fraction) in [(false, ""), (true, ".123456")] {
            let text = format!("{}{hours}:59:59{fraction}", if negative { "-" } else { "" });
            let mut actual = vec![];
            crate::MySqlTextValue(text.as_bytes())
                .to_mysql_bin(&mut actual, &column)
                .unwrap();
            let mut expected = vec![if fraction.is_empty() { 8 } else { 12 }, u8::from(negative)];
            expected.extend((days as u32).to_le_bytes());
            expected.extend([hour, 59, 59]);
            if !fraction.is_empty() {
                expected.extend(123456_u32.to_le_bytes());
            }
            assert_eq!(actual, expected, "{text}");
            let mut text_bytes = vec![];
            crate::MySqlTextValue(text.as_bytes())
                .to_mysql_text(&mut text_bytes)
                .unwrap();
            assert_eq!(&text_bytes[1..], text.as_bytes());
        }
    }
    for text in ["2400:00:00", "-2400:00:00", "2399:60:00", "2399:00:60"] {
        assert!(
            crate::MySqlTextValue(text.as_bytes())
                .to_mysql_bin(&mut vec![], &column)
                .is_err(),
            "{text}"
        );
    }
}
