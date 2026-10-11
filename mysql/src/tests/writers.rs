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

use std::io::Write as _;

mod metadata {
    use crate::packet_writer::PacketWriter;
    use crate::writers::*;
    use crate::{Column, ColumnFlags, ColumnType, OkResponse, StatusFlags};
    use mysql_common::constants::CapabilityFlags;
    use mysql_common::io::ParseBuf;
    use mysql_common::packets::{OkPacket, OkPacketDeserializer, ResultSetTerminator};
    use tokio::io::AsyncReadExt;

    fn parse_lenenc_int(buf: &[u8]) -> (u64, usize) {
        match buf[0] {
            v @ 0x00..=0xfa => (v as u64, 1),
            0xfc => {
                let len = u16::from_le_bytes([buf[1], buf[2]]);
                (len as u64, 3)
            }
            0xfd => {
                let len = (buf[1] as u32) | ((buf[2] as u32) << 8) | ((buf[3] as u32) << 16);
                (len as u64, 4)
            }
            0xfe => {
                let len = u64::from_le_bytes([
                    buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
                ]);
                (len, 9)
            }
            marker => panic!("unexpected length-encoded integer marker: {marker:#x}"),
        }
    }

    async fn extract_payload_with_header(
        info: &str,
        capabilities: CapabilityFlags,
        header: u8,
    ) -> Vec<u8> {
        let (mut client, server) = tokio::io::duplex(1024);
        let mut writer = PacketWriter::new(server);

        let ok_packet = OkResponse {
            header,
            info: info.to_string(),
            ..Default::default()
        };

        write_ok_packet(&mut writer, capabilities, ok_packet)
            .await
            .expect("write_ok_packet succeeds");

        let mut header = [0u8; 4];
        client
            .read_exact(&mut header)
            .await
            .expect("payload header available");
        let payload_len =
            (header[0] as usize) | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
        let mut payload = vec![0u8; payload_len];
        client
            .read_exact(&mut payload)
            .await
            .expect("payload body available");
        payload
    }

    async fn extract_payload(info: &str, capabilities: CapabilityFlags) -> Vec<u8> {
        extract_payload_with_header(info, capabilities, 0x00).await
    }

    fn consume_ok_packet_prefix(payload: &[u8]) -> (usize, u16, u16) {
        let mut idx = 0;
        assert_eq!(payload[idx], 0x00);
        idx += 1;

        let (affected_rows, consumed) = parse_lenenc_int(&payload[idx..]);
        assert_eq!(affected_rows, 0);
        idx += consumed;

        let (last_insert_id, consumed) = parse_lenenc_int(&payload[idx..]);
        assert_eq!(last_insert_id, 0);
        idx += consumed;

        let status = u16::from_le_bytes([payload[idx], payload[idx + 1]]);
        idx += 2;

        let warnings = u16::from_le_bytes([payload[idx], payload[idx + 1]]);
        idx += 2;

        (idx, status, warnings)
    }

    #[test]
    fn column_charset_defaults_to_utf8() {
        let column = Column {
            database: Vec::new(),
            org_table: Vec::new(),
            org_column: Vec::new(),
            table: "t".into(),
            column: "c".into(),
            collen: 0,
            charset: None,
            coltype: ColumnType::MYSQL_TYPE_VAR_STRING,
            colflags: ColumnFlags::empty(),
            decimals: None,
        };

        assert_eq!(column_charset(&column), 33);
    }

    #[test]
    fn column_charset_uses_binary_for_numeric_types() {
        let column = Column {
            database: Vec::new(),
            org_table: Vec::new(),
            org_column: Vec::new(),
            table: "t".into(),
            column: "c".into(),
            collen: 0,
            charset: None,
            coltype: ColumnType::MYSQL_TYPE_LONG,
            colflags: ColumnFlags::empty(),
            decimals: None,
        };

        assert_eq!(column_charset(&column), 63);
    }

    #[test]
    fn column_charset_uses_binary_when_flagged() {
        let column = Column {
            database: Vec::new(),
            org_table: Vec::new(),
            org_column: Vec::new(),
            table: "t".into(),
            column: "c".into(),
            collen: 0,
            charset: None,
            coltype: ColumnType::MYSQL_TYPE_STRING,
            colflags: ColumnFlags::BINARY_FLAG,
            decimals: None,
        };

        assert_eq!(column_charset(&column), 63);
    }

    #[test]
    fn column_charset_handles_blob_types() {
        let column = Column {
            database: Vec::new(),
            org_table: Vec::new(),
            org_column: Vec::new(),
            table: "t".into(),
            column: "c".into(),
            collen: 0,
            charset: None,
            coltype: ColumnType::MYSQL_TYPE_BLOB,
            colflags: ColumnFlags::empty(),
            decimals: None,
        };

        assert_eq!(column_charset(&column), 63);
    }

    #[test]
    fn column_charset_respects_blob_flag() {
        let column = Column {
            database: Vec::new(),
            org_table: Vec::new(),
            org_column: Vec::new(),
            table: "t".into(),
            column: "c".into(),
            collen: 0,
            charset: None,
            coltype: ColumnType::MYSQL_TYPE_VAR_STRING,
            colflags: ColumnFlags::BLOB_FLAG,
            decimals: None,
        };

        assert_eq!(column_charset(&column), 63);
    }

    #[tokio::test]
    async fn column_definition_preserves_zero_length_for_null_type() {
        let (mut client, server) = tokio::io::duplex(1024);
        let mut writer = PacketWriter::new(server);
        let column = Column {
            database: Vec::new(),
            org_table: Vec::new(),
            org_column: Vec::new(),
            table: Vec::new(),
            column: b"null_value".to_vec(),
            collen: 0,
            charset: Some(63),
            coltype: ColumnType::MYSQL_TYPE_NULL,
            colflags: ColumnFlags::BINARY_FLAG | ColumnFlags::NUM_FLAG,
            decimals: Some(0),
        };
        write_column_definitions_41(
            [&column],
            &mut writer,
            CapabilityFlags::CLIENT_DEPRECATE_EOF,
            false,
        )
        .await
        .unwrap();
        let mut header = [0; 4];
        client.read_exact(&mut header).await.unwrap();
        let length =
            (header[0] as usize) | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
        let mut payload = vec![0; length];
        client.read_exact(&mut payload).await.unwrap();
        let mut offset = 0;
        for _ in 0..6 {
            let (length, consumed) = parse_lenenc_int(&payload[offset..]);
            offset += consumed + length as usize;
        }
        let (fixed_length, consumed) = parse_lenenc_int(&payload[offset..]);
        assert_eq!(fixed_length, 12);
        offset += consumed + 2;
        let column_length = u32::from_le_bytes(
            payload[offset..offset + 4]
                .try_into()
                .expect("column length bytes"),
        );
        assert_eq!(column_length, 0);
    }

    #[tokio::test]
    async fn com_field_list_uses_ok_terminator_when_eof_is_deprecated() {
        let (mut client, server) = tokio::io::duplex(1024);
        let mut writer = PacketWriter::new(server);
        let column = Column {
            database: b"db".to_vec(),
            org_table: b"v".to_vec(),
            org_column: b"c".to_vec(),
            table: b"v".to_vec(),
            column: b"c".to_vec(),
            collen: 16,
            charset: None,
            coltype: ColumnType::MYSQL_TYPE_VAR_STRING,
            colflags: ColumnFlags::empty(),
            decimals: Some(0),
        };
        write_column_definitions_41(
            [&column],
            &mut writer,
            CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_DEPRECATE_EOF,
            true,
        )
        .await
        .unwrap();

        for expected_first_byte in [3, 0xfe] {
            let mut header = [0; 4];
            client.read_exact(&mut header).await.unwrap();
            let length =
                (header[0] as usize) | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
            let mut payload = vec![0; length];
            client.read_exact(&mut payload).await.unwrap();
            assert_eq!(payload[0], expected_first_byte);
            if expected_first_byte == 0xfe {
                assert!(
                    payload.len() >= 7,
                    "deprecated-EOF terminator is an OK packet"
                );
            }
        }
    }

    #[tokio::test]
    async fn ok_packet_info_is_length_encoded_with_session_track() {
        let info = "Read 1 rows, 1.00 B in 0.007 sec.";
        let capabilities =
            CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_SESSION_TRACK;
        let payload = extract_payload(info, capabilities).await;

        let (mut idx, status, warnings) = consume_ok_packet_prefix(&payload);
        assert_eq!(status, 0);
        assert_eq!(warnings, 0);

        let (info_len, consumed) = parse_lenenc_int(&payload[idx..]);
        assert_eq!(info_len as usize, info.len());
        assert_eq!(payload[idx], info.len() as u8);
        idx += consumed;

        let encoded = &payload[idx..idx + info.len()];
        assert_eq!(encoded, info.as_bytes());
    }

    #[tokio::test]
    async fn ok_packet_info_uses_extended_length_prefix_when_needed() {
        let info = "x".repeat(300);
        let capabilities =
            CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_SESSION_TRACK;
        let payload = extract_payload(&info, capabilities).await;

        let (mut idx, status, warnings) = consume_ok_packet_prefix(&payload);
        assert_eq!(status, 0);
        assert_eq!(warnings, 0);

        let (info_len, consumed) = parse_lenenc_int(&payload[idx..]);
        assert_eq!(consumed, 3, "expected 0xFC marker with two-byte length");
        assert_eq!(payload[idx], 0xFC);
        assert_eq!(info_len as usize, info.len());
        idx += consumed;

        let encoded = &payload[idx..idx + info.len()];
        assert_eq!(encoded, info.as_bytes());
    }

    #[tokio::test]
    async fn ok_packet_skips_info_for_empty_string_without_session_track() {
        let payload = extract_payload("", CapabilityFlags::CLIENT_PROTOCOL_41).await;

        let (idx, status, warnings) = consume_ok_packet_prefix(&payload);
        assert_eq!(status, 0);
        assert_eq!(warnings, 0);
        assert_eq!(
            idx,
            payload.len(),
            "empty info without CLIENT_SESSION_TRACK should not emit length prefix"
        );
    }

    #[tokio::test]
    async fn ok_packet_info_is_length_encoded_without_session_track() {
        let info = "Read 1 rows, 1.00 B in 0.007 sec.";
        let payload = extract_payload(info, CapabilityFlags::CLIENT_PROTOCOL_41).await;

        let (mut idx, status, warnings) = consume_ok_packet_prefix(&payload);
        assert_eq!(status, 0);
        assert_eq!(warnings, 0);

        let (info_len, consumed) = parse_lenenc_int(&payload[idx..]);
        assert_eq!(info_len as usize, info.len());
        idx += consumed;
        let encoded = &payload[idx..idx + info.len()];
        assert_eq!(encoded, info.as_bytes());
    }

    #[tokio::test]
    async fn ok_packet_with_deprecate_eof_parses_lenenc_info() {
        let info = "x".repeat(300);
        let capabilities = CapabilityFlags::CLIENT_PROTOCOL_41
            | CapabilityFlags::CLIENT_DEPRECATE_EOF
            | CapabilityFlags::CLIENT_SESSION_TRACK;
        let payload = extract_payload_with_header(&info, capabilities, 0xfe).await;

        let mut buf = ParseBuf(&payload);
        let ok_packet: OkPacket = buf
            .parse::<OkPacketDeserializer<ResultSetTerminator>>(capabilities)
            .expect("ResultSetTerminator packet to parse")
            .into_inner();
        assert_eq!(ok_packet.info_ref(), Some(info.as_bytes()));
        assert_eq!(ok_packet.status_flags(), StatusFlags::empty());
    }
}

use flate2::read::ZlibDecoder;
use tokio::io::{duplex, AsyncReadExt};

use crate::packet_writer::PacketWriter;
use crate::writers::{
    write_eof_packet, write_err, write_err_raw, write_ok_packet, write_prepare_ok,
};
use crate::U24_MAX;
use crate::{CapabilityFlags, ErrorKind, OkResponse, StatusFlags};

async fn capture_packet<F, Fut>(write: F) -> Vec<u8>
where
    F: FnOnce(PacketWriter<tokio::io::DuplexStream>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let (mut client, server) = duplex(4096);
    write(PacketWriter::new(server)).await;
    let mut header = [0u8; 4];
    client.read_exact(&mut header).await.unwrap();
    let length = header[0] as usize | (header[1] as usize) << 8 | (header[2] as usize) << 16;
    let mut packet = header.to_vec();
    packet.resize(4 + length, 0);
    client.read_exact(&mut packet[4..]).await.unwrap();
    packet
}

#[tokio::test]
async fn mysql80_ok_err_and_eof_packets_match_protocol_goldens() {
    let ok = capture_packet(|mut writer| async move {
        write_ok_packet(
            &mut writer,
            CapabilityFlags::CLIENT_PROTOCOL_41,
            OkResponse {
                affected_rows: 2,
                last_insert_id: 3,
                status_flags: StatusFlags::SERVER_STATUS_AUTOCOMMIT,
                warnings: 1,
                info: "ok".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    })
    .await;
    assert_eq!(
        ok,
        [
            10, 0, 0, 0, // classic header
            0x00, 2, 3, 2, 0, 1, 0, 2, b'o', b'k'
        ]
    );

    let err = capture_packet(|mut writer| async move {
        write_err(
            ErrorKind::ER_BAD_TABLE_ERROR,
            b"Unknown table 't'",
            &mut writer,
        )
        .await
        .unwrap();
    })
    .await;
    let mut expected_err = vec![26, 0, 0, 0, 0xff];
    expected_err.extend_from_slice(&(ErrorKind::ER_BAD_TABLE_ERROR as u16).to_le_bytes());
    expected_err.extend_from_slice(b"#42S02Unknown table 't'");
    assert_eq!(err, expected_err);

    let eof = capture_packet(|mut writer| async move {
        write_eof_packet(&mut writer, StatusFlags::SERVER_STATUS_AUTOCOMMIT, 7)
            .await
            .unwrap();
    })
    .await;
    assert_eq!(eof, [5, 0, 0, 0, 0xfe, 7, 0, 2, 0]);
}

#[tokio::test]
async fn raw_error_packet_preserves_vendor_number_and_sqlstate() {
    let packet = capture_packet(|mut writer| async move {
        write_err_raw(30_001, b"45000", b"raised by SIGNAL", &mut writer)
            .await
            .unwrap();
    })
    .await;
    let mut expected = vec![0, 0, 0, 0, 0xff];
    expected.extend_from_slice(&30_001u16.to_le_bytes());
    expected.extend_from_slice(b"#45000raised by SIGNAL");
    expected[0] = (expected.len() - 4) as u8;
    assert_eq!(packet, expected);
}

#[tokio::test]
async fn prepare_ok_packet_carries_metadata_warning_count() {
    let packet = capture_packet(|mut writer| async move {
        write_prepare_ok(
            42,
            std::iter::empty(),
            std::iter::empty(),
            3,
            &mut writer,
            CapabilityFlags::CLIENT_PROTOCOL_41,
            true,
        )
        .await
        .unwrap();
    })
    .await;
    assert_eq!(
        packet,
        [
            12, 0, 0, 0, // classic header
            0x00, 42, 0, 0, 0, // status and statement id
            0, 0, // columns
            0, 0, // parameters
            0, // reserved
            3, 0, // warnings
        ]
    );
}

async fn capture_ok_payload(info: &str, capabilities: CapabilityFlags, header: u8) -> Vec<u8> {
    let (mut client, server) = duplex(1024);
    let mut writer = PacketWriter::new(server);

    let ok_packet = OkResponse {
        header,
        info: info.to_string(),
        ..Default::default()
    };

    write_ok_packet(&mut writer, capabilities, ok_packet)
        .await
        .expect("write_ok_packet succeeds");

    let mut header_buf = [0u8; 4];
    client
        .read_exact(&mut header_buf)
        .await
        .expect("payload header available");
    let payload_len = (header_buf[0] as usize)
        | ((header_buf[1] as usize) << 8)
        | ((header_buf[2] as usize) << 16);
    let mut payload = vec![0u8; payload_len];
    client
        .read_exact(&mut payload)
        .await
        .expect("payload body available");
    payload
}

fn parse_lenenc_int(data: &[u8]) -> (u64, usize) {
    match data[0] {
        0xFC => {
            let len = u16::from_le_bytes([data[1], data[2]]) as u64;
            (len, 3)
        }
        0xFD => {
            let len = (data[1] as u64) | ((data[2] as u64) << 8) | ((data[3] as u64) << 16);
            (len, 4)
        }
        0xFE => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[1..9]);
            (u64::from_le_bytes(buf), 9)
        }
        v => (v as u64, 1),
    }
}

fn consume_ok_prefix(payload: &[u8]) -> (usize, u8, u16, u16) {
    let mut idx = 0;
    let header = payload[idx];
    idx += 1;

    let (affected_rows, consumed) = parse_lenenc_int(&payload[idx..]);
    assert_eq!(affected_rows, 0);
    idx += consumed;

    let (last_insert_id, consumed) = parse_lenenc_int(&payload[idx..]);
    assert_eq!(last_insert_id, 0);
    idx += consumed;

    let status = u16::from_le_bytes([payload[idx], payload[idx + 1]]);
    idx += 2;

    let warnings = u16::from_le_bytes([payload[idx], payload[idx + 1]]);
    idx += 2;

    (idx, header, status, warnings)
}

#[tokio::test]
async fn ok_packet_info_lenenc_when_session_track() {
    let info = "Read 1 rows, 1.00 B in 0.007 sec.";
    let payload = capture_ok_payload(
        info,
        CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_SESSION_TRACK,
        0x00,
    )
    .await;

    let (mut idx, header, status, warnings) = consume_ok_prefix(&payload);
    assert_eq!(header, 0x00);
    assert_eq!(status, 0);
    assert_eq!(warnings, 0);

    let (info_len, consumed) = parse_lenenc_int(&payload[idx..]);
    assert_eq!(info_len as usize, info.len());
    idx += consumed;

    let encoded = &payload[idx..idx + info.len()];
    assert_eq!(encoded, info.as_bytes());
}

#[tokio::test]
async fn ok_packet_info_lenenc_when_deprecate_eof() {
    let info = "Read 1 rows, 1.00 B in 0.007 sec.";
    let payload = capture_ok_payload(
        info,
        CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_DEPRECATE_EOF,
        0x00,
    )
    .await;

    let (mut idx, header, status, warnings) = consume_ok_prefix(&payload);
    assert_eq!(header, 0x00);
    assert_eq!(status, 0);
    assert_eq!(warnings, 0);

    let (info_len, consumed) = parse_lenenc_int(&payload[idx..]);
    assert_eq!(info_len as usize, info.len());
    idx += consumed;

    let encoded = &payload[idx..idx + info.len()];
    assert_eq!(encoded, info.as_bytes());
}

#[tokio::test]
async fn ok_packet_info_lenenc_when_header_fe() {
    let info = "Read 1 rows, 1.00 B in 0.007 sec.";
    let payload = capture_ok_payload(info, CapabilityFlags::CLIENT_PROTOCOL_41, 0xfe).await;

    let (mut idx, header, status, warnings) = consume_ok_prefix(&payload);
    assert_eq!(header, 0xfe);
    assert_eq!(status, 0);
    assert_eq!(warnings, 0);

    let (info_len, consumed) = parse_lenenc_int(&payload[idx..]);
    assert_eq!(info_len as usize, info.len());
    idx += consumed;

    let encoded = &payload[idx..idx + info.len()];
    assert_eq!(encoded, info.as_bytes());
}

#[tokio::test]
async fn ok_packet_info_lenenc_when_no_flags() {
    let info = "Read 1 rows, 1.00 B in 0.007 sec.";
    let payload = capture_ok_payload(info, CapabilityFlags::CLIENT_PROTOCOL_41, 0x00).await;

    let (mut idx, header, status, warnings) = consume_ok_prefix(&payload);
    assert_eq!(header, 0x00);
    assert_eq!(status, 0);
    assert_eq!(warnings, 0);

    let (info_len, consumed) = parse_lenenc_int(&payload[idx..]);
    assert_eq!(info_len as usize, info.len());
    idx += consumed;
    let encoded = &payload[idx..idx + info.len()];
    assert_eq!(encoded, info.as_bytes());
}

#[tokio::test]
async fn ok_packet_info_extended_lenenc_with_flags() {
    let info = "x".repeat(300);
    let payload = capture_ok_payload(
        &info,
        CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_SESSION_TRACK,
        0x00,
    )
    .await;

    let (mut idx, header, status, warnings) = consume_ok_prefix(&payload);
    assert_eq!(header, 0x00);
    assert_eq!(status, 0);
    assert_eq!(warnings, 0);

    let (info_len, consumed) = parse_lenenc_int(&payload[idx..]);
    assert_eq!(consumed, 3); // expect 0xFC marker with two-byte length
    assert_eq!(payload[idx], 0xFC);
    assert_eq!(info_len as usize, info.len());
    idx += consumed;

    let encoded = &payload[idx..idx + info.len()];
    assert_eq!(encoded, info.as_bytes());
}

#[tokio::test]
async fn compressed_writer_preserves_classic_fragment_headers() {
    let payload = vec![b'x'; U24_MAX + 17];
    let (mut client, server) = duplex(4096);
    let task = tokio::spawn(async move {
        let mut writer = PacketWriter::new(server);
        writer.enable_compression();
        writer.write_all(&payload).unwrap();
        writer.end_packet().await.unwrap();
        writer.flush_all().await.unwrap();
    });

    let mut classic = Vec::new();
    while classic.len() < U24_MAX + 17 + 8 {
        let mut header = [0u8; 7];
        client.read_exact(&mut header).await.unwrap();
        let compressed_len =
            header[0] as usize | (header[1] as usize) << 8 | (header[2] as usize) << 16;
        let uncompressed_len =
            header[4] as usize | (header[5] as usize) << 8 | (header[6] as usize) << 16;
        let mut frame = vec![0u8; compressed_len];
        client.read_exact(&mut frame).await.unwrap();
        if uncompressed_len == 0 {
            classic.extend_from_slice(&frame);
        } else {
            use std::io::Read as _;
            let mut decoder = ZlibDecoder::new(frame.as_slice());
            let before = classic.len();
            decoder.read_to_end(&mut classic).unwrap();
            assert_eq!(classic.len() - before, uncompressed_len);
        }
    }
    task.await.unwrap();

    assert_eq!(&classic[..4], &[0xff, 0xff, 0xff, 0]);
    let second = 4 + U24_MAX;
    assert_eq!(&classic[second..second + 4], &[17, 0, 0, 1]);
    assert_eq!(classic.len(), U24_MAX + 17 + 8);
}

#[tokio::test]
async fn compressed_writer_uses_the_request_frame_sequence_for_its_response() {
    let (mut client, server) = duplex(1024);
    let task = tokio::spawn(async move {
        let mut writer = PacketWriter::new(server);
        writer.enable_zstd_compression(3);
        writer.set_seq(1);
        writer.set_compressed_sequence(2);
        writer.write_all(b"response").unwrap();
        writer.end_packet().await.unwrap();
        writer.flush_all().await.unwrap();
    });

    let mut header = [0u8; 7];
    client.read_exact(&mut header).await.unwrap();
    assert_eq!(header[3], 2);
    let compressed_len =
        header[0] as usize | (header[1] as usize) << 8 | (header[2] as usize) << 16;
    let uncompressed_len =
        header[4] as usize | (header[5] as usize) << 8 | (header[6] as usize) << 16;
    let mut payload = vec![0u8; compressed_len];
    client.read_exact(&mut payload).await.unwrap();
    let plain = if uncompressed_len == 0 {
        payload
    } else {
        zstd::stream::decode_all(payload.as_slice()).unwrap()
    };
    assert_eq!(&plain[..4], &[8, 0, 0, 1]);
    assert_eq!(&plain[4..], b"response");
    task.await.unwrap();
}

#[tokio::test]
async fn prepared_out_parameter_status_precedes_the_following_command_result() {
    use crate::QueryResultWriter;

    async fn read_packet(stream: &mut tokio::io::DuplexStream) -> Vec<u8> {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await.unwrap();
        let length = header[0] as usize | (header[1] as usize) << 8 | (header[2] as usize) << 16;
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).await.unwrap();
        payload
    }

    let (mut client, server) = duplex(1024);
    let mut packets = PacketWriter::new(server);
    QueryResultWriter::new(
        &mut packets,
        true,
        CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_PS_MULTI_RESULTS,
    )
    .complete_one(OkResponse {
        status_flags: StatusFlags::SERVER_PS_OUT_PARAMS,
        ..Default::default()
    })
    .await
    .unwrap()
    .complete_one(OkResponse {
        affected_rows: 1,
        ..Default::default()
    })
    .await
    .unwrap()
    .no_more_results()
    .await
    .unwrap();

    let out_parameters = read_packet(&mut client).await;
    let command = read_packet(&mut client).await;
    let status = |payload: &[u8]| {
        StatusFlags::from_bits_truncate(u16::from_le_bytes([payload[3], payload[4]]))
    };
    assert!(status(&out_parameters).contains(StatusFlags::SERVER_PS_OUT_PARAMS));
    assert!(status(&out_parameters).contains(StatusFlags::SERVER_MORE_RESULTS_EXISTS));
    assert!(!status(&command).contains(StatusFlags::SERVER_PS_OUT_PARAMS));
    assert!(!status(&command).contains(StatusFlags::SERVER_MORE_RESULTS_EXISTS));
    assert_eq!(command[1], 1, "the following OK is the CALL command result");
}
