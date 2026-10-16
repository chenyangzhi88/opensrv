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

use std::io::Cursor;

use crate::commands::*;
use crate::myc::constants::{CapabilityFlags, UTF8_GENERAL_CI};
use crate::packet_reader::PacketReader;

#[test]
fn handshake_attributes_are_required_only_when_both_peers_support_them() {
    for after_tls in [false, true] {
        for client_supports in [false, true] {
            for server_supports in [false, true] {
                let mut client =
                    CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_PLUGIN_AUTH;
                client.set(CapabilityFlags::CLIENT_CONNECT_ATTRS, client_supports);
                let mut server =
                    CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_PLUGIN_AUTH;
                server.set(CapabilityFlags::CLIENT_CONNECT_ATTRS, server_supports);
                let mut input = client.bits().to_le_bytes().to_vec();
                input.extend_from_slice(&1024u32.to_le_bytes());
                input.push(45);
                input.extend_from_slice(&[0; 23]);
                input.extend_from_slice(b"login\0\0mysql_native_password\0");
                if client_supports && server_supports {
                    assert!(
                        client_handshake(&input, after_tls, server).is_err(),
                        "negotiated attributes require the real length byte"
                    );
                    input.extend_from_slice(&[4, 1, b'k', 1, b'v']);
                }
                let (remaining, handshake) = client_handshake(&input, after_tls, server).unwrap();
                assert!(remaining.is_empty());
                assert_eq!(
                    handshake.capabilities, client,
                    "retain original client flags independently from field negotiation"
                );
                assert_eq!(handshake.username.as_deref(), Some(b"login".as_slice()));
                assert_eq!(handshake.auth_plugin, b"mysql_native_password");
                assert_eq!(
                    handshake.connection_attrs,
                    if client_supports && server_supports {
                        b"\x01k\x01v".to_vec()
                    } else {
                        vec![]
                    }
                );
            }
        }
    }
}

#[test]
fn zstd_level_receipt_preserves_missing_and_invalid_bytes_without_inventing_a_default() {
    for declared in [false, true] {
        for level in [None, Some(0), Some(1), Some(22), Some(23), Some(255)] {
            let mut capabilities = CapabilityFlags::CLIENT_PROTOCOL_41;
            capabilities.set(CapabilityFlags::CLIENT_ZSTD_COMPRESSION_ALGORITHM, declared);
            let mut bytes = capabilities.bits().to_le_bytes().to_vec();
            bytes.extend_from_slice(&1024u32.to_le_bytes());
            bytes.push(UTF8_GENERAL_CI as u8);
            bytes.extend_from_slice(&[0; 23]);
            bytes.extend_from_slice(b"login\0\0");
            if let Some(level) = level {
                bytes.push(level);
            }
            let (remaining, handshake) = client_handshake(&bytes, false, capabilities).unwrap();
            assert_eq!(
                handshake.zstd_compression_level,
                if declared { level } else { None }
            );
            assert_eq!(
                remaining,
                if declared {
                    &[][..]
                } else {
                    bytes.get(39..).unwrap()
                }
            );
        }
    }
}

#[test]
fn protocol41_auth_encodings_keep_database_plugin_and_attributes_at_the_actual_boundary() {
    let base = CapabilityFlags::CLIENT_PROTOCOL_41
        | CapabilityFlags::CLIENT_CONNECT_WITH_DB
        | CapabilityFlags::CLIENT_PLUGIN_AUTH
        | CapabilityFlags::CLIENT_CONNECT_ATTRS;
    for extra in [
        CapabilityFlags::empty(),
        CapabilityFlags::CLIENT_SECURE_CONNECTION,
        CapabilityFlags::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA,
    ] {
        for password in [&b""[..], &b"password"[..]] {
            let capabilities = base | extra;
            let mut input = capabilities.bits().to_le_bytes().to_vec();
            input.extend_from_slice(&1024u32.to_le_bytes());
            input.push(45);
            input.extend_from_slice(&[0; 23]);
            input.extend_from_slice(b"login\0");
            input.push(password.len() as u8);
            input.extend_from_slice(password);
            input.extend_from_slice(b"database\0mysql_native_password\0");
            input.extend_from_slice(&[4, 1, b'k', 1, b'v']);
            let (tail, handshake) = client_handshake(&input, false, capabilities).unwrap();
            assert!(tail.is_empty());
            assert_eq!(handshake.username.as_deref(), Some(&b"login"[..]));
            assert_eq!(handshake.auth_response, password);
            assert_eq!(handshake.db.as_deref(), Some(&b"database"[..]));
            assert_eq!(handshake.auth_plugin, b"mysql_native_password");
            assert_eq!(handshake.connection_attrs, b"\x01k\x01v".to_vec());
        }
    }
    // An absent or oversized auth length must not consume a declared DB or
    // silently default that mandatory field. Protocol41 is not the pre-4.1
    // NUL-terminated password format, with or without SECURE_CONNECTION.
    let mut input = base.bits().to_le_bytes().to_vec();
    input.extend_from_slice(&1024u32.to_le_bytes());
    input.push(45);
    input.extend_from_slice(&[0; 23]);
    input.extend_from_slice(b"login\0");
    assert!(client_handshake(&input, false, base).is_err());
    input.push(10);
    input.extend_from_slice(b"short");
    assert!(client_handshake(&input, false, base).is_err());
    input.truncate(38);
    input.push(0);
    assert!(client_handshake(&input, false, base).is_err());

    let password = vec![b'a'; 300];
    let capabilities = base | CapabilityFlags::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;
    let mut input = capabilities.bits().to_le_bytes().to_vec();
    input.extend_from_slice(&1024u32.to_le_bytes());
    input.push(45);
    input.extend_from_slice(&[0; 23]);
    input.extend_from_slice(b"login\0");
    input.extend_from_slice(&[0xfc, 0x2c, 0x01]);
    input.extend_from_slice(&password);
    input.extend_from_slice(b"database\0mysql_native_password\0");
    input.extend_from_slice(&[4, 1, b'k', 1, b'v']);
    let (tail, handshake) = client_handshake(&input, false, capabilities).unwrap();
    assert!(tail.is_empty());
    assert_eq!(handshake.auth_response, password);
    assert_eq!(handshake.db.as_deref(), Some(&b"database"[..]));
    assert_eq!(handshake.connection_attrs, b"\x01k\x01v".to_vec());
}

#[test]
fn declared_connection_attributes_require_length_and_reject_native_64k_overflow() {
    let capabilities = CapabilityFlags::CLIENT_PROTOCOL_41
        | CapabilityFlags::CLIENT_PLUGIN_AUTH
        | CapabilityFlags::CLIENT_CONNECT_ATTRS;
    let mut input = capabilities.bits().to_le_bytes().to_vec();
    input.extend_from_slice(&1024u32.to_le_bytes());
    input.push(45);
    input.extend_from_slice(&[0; 23]);
    input.extend_from_slice(b"login\0\0mysql_native_password\0");
    assert!(client_handshake(&input, false, capabilities).is_err());
    let boundary = input.len();
    input.extend_from_slice(&[0xfd, 0, 0, 1]);
    input.extend_from_slice(&vec![0; 65_536]);
    assert!(matches!(
        client_handshake(&input, false, capabilities),
        Err(nom::Err::Failure(_))
    ));
    input.truncate(boundary);
    // A real 65535-byte attribute block remains legal: one key and one
    // length-encoded value, no new table or opaque trailing padding.
    input.extend_from_slice(&[0xfc, 0xff, 0xff, 1, b'k', 0xfc, 0xfa, 0xff]);
    input.extend_from_slice(&vec![b'v'; 65_530]);
    let (tail, handshake) = client_handshake(&input, false, capabilities).unwrap();
    assert!(tail.is_empty());
    assert_eq!(
        handshake.connection_attrs,
        [b"\x01k\xfc\xfa\xff".as_slice(), &vec![b'v'; 65_530]].concat()
    );
}

#[test]
fn native_attribute_outer_null_is_rejected_and_nine_byte_marker_keeps_uint64_length() {
    let capabilities = CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_CONNECT_ATTRS;
    let parse = |outer: &[u8]| {
        let mut input = capabilities.bits().to_le_bytes().to_vec();
        input.extend_from_slice(&1024u32.to_le_bytes());
        input.push(33);
        input.extend_from_slice(&[0; 23]);
        input.extend_from_slice(b"login\0\0");
        input.extend_from_slice(outer);
        client_handshake(&input, false, capabilities)
            .map(|(remaining, handshake)| {
                assert!(remaining.is_empty());
                handshake.connection_attrs
            })
            .map_err(|error| error.to_owned())
    };
    assert!(parse(b"\xfb").is_err());
    for marker in [0xfe, 0xff] {
        assert_eq!(
            parse(&[marker, 4, 0, 0, 0, 0, 0, 0, 0, 1, b'k', 1, b'v']).unwrap(),
            b"\x01k\x01v"
        );
        assert!(
            parse(&[marker, 4, 0, 0, 0, 1, 0, 0, 0, 1, b'k', 1, b'v']).is_err(),
            "outer native length is uint64, unlike PFS inner low uint32"
        );
    }
}

#[test]
fn handshake_retains_malformed_inner_lenenc_and_non_utf8_as_raw_native_payload() {
    let capabilities = CapabilityFlags::CLIENT_PROTOCOL_41 | CapabilityFlags::CLIENT_CONNECT_ATTRS;
    for raw in [
        b"\x01k\x01\xff".as_slice(),
        b"\xfb",
        b"\xfc\x01",
        b"\x01k\x05v",
    ] {
        let mut input = capabilities.bits().to_le_bytes().to_vec();
        input.extend_from_slice(&1024u32.to_le_bytes());
        input.push(33);
        input.extend_from_slice(&[0; 23]);
        input.extend_from_slice(b"login\0\0");
        input.push(raw.len() as u8);
        input.extend_from_slice(raw);
        let (tail, handshake) = client_handshake(&input, false, capabilities).unwrap();
        assert!(tail.is_empty());
        assert_eq!(handshake.connection_attrs, raw);
        assert_eq!(handshake.collation, 33);
    }
}

#[test]
fn it_parses_handshake() {
    let data = &[
        0x5c, 0x00, 0x00, 0x01, 0x8d, 0xa6, 0xff, 0x09, 0x00, 0x00, 0x00, 0x01, 0x21, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x00, 0x14,
        0xf7, 0xd1, 0x6c, 0xe9, 0x0d, 0x2f, 0x34, 0xb0, 0x2f, 0xd8, 0x1d, 0x18, 0xc7, 0xa4, 0xe8,
        0x98, 0x97, 0x67, 0xeb, 0xad, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x00, 0x6d, 0x79,
        0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73,
        0x77, 0x6f, 0x72, 0x64, 0x00, 0x00, // declared empty connection attributes
    ];

    let r = Cursor::new(&data[..]);
    let mut pr = PacketReader::new(r);
    let (_, p) = pr.next().unwrap().unwrap();
    let (_, handshake) = client_handshake(&p, false, CapabilityFlags::all()).unwrap();
    println!("{handshake:?}");
    assert!(handshake
        .capabilities
        .contains(CapabilityFlags::CLIENT_LONG_PASSWORD));
    assert!(handshake
        .capabilities
        .contains(CapabilityFlags::CLIENT_MULTI_RESULTS));
    assert!(handshake
        .capabilities
        .contains(CapabilityFlags::CLIENT_CONNECT_WITH_DB));
    assert!(handshake
        .capabilities
        .contains(CapabilityFlags::CLIENT_DEPRECATE_EOF));
    assert_eq!(handshake.collation, UTF8_GENERAL_CI);
    assert_eq!(handshake.username, Some(b"default"[..].to_vec()));
    assert_eq!(handshake.maxps, 16777216);
}

#[test]
fn it_parses_request() {
    let data = &[
        0x21, 0x00, 0x00, 0x00, 0x03, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x40, 0x40, 0x76,
        0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20,
        0x6c, 0x69, 0x6d, 0x69, 0x74, 0x20, 0x31,
    ];
    let r = Cursor::new(&data[..]);
    let mut pr = PacketReader::new(r);
    let (_, p) = pr.next().unwrap().unwrap();
    let (_, cmd) = parse(&p).unwrap();
    assert_eq!(
        cmd,
        Command::Query(&b"select @@version_comment limit 1"[..])
    );
}

#[test]
fn it_handles_list_fields() {
    // mysql_list_fields (CommandByte::COM_FIELD_LIST / 0x04) has been deprecated in mysql 5.7 and will be removed
    // in a future version. The mysql command line tool issues one of these commands after
    // switching databases with USE <DB>.
    let data = &[
        0x21, 0x00, 0x00, 0x00, 0x04, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x40, 0x40, 0x76,
        0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20,
        0x6c, 0x69, 0x6d, 0x69, 0x74, 0x20, 0x31,
    ];
    let r = Cursor::new(&data[..]);
    let mut pr = PacketReader::new(r);
    let (_, p) = pr.next().unwrap().unwrap();
    let (_, cmd) = parse(&p).unwrap();
    assert_eq!(
        cmd,
        Command::ListFields(&b"select @@version_comment limit 1"[..])
    );
}

#[test]
fn unknown_command_is_not_silently_accepted() {
    let (_, command) = parse(&[0xff, 1, 2, 3]).unwrap();
    assert_eq!(command, Command::Unknown(0xff));
}

#[test]
fn parses_classic_administrative_commands() {
    assert_eq!(
        parse(&[5, b'd', b'b']).unwrap().1,
        Command::CreateDatabase(b"db")
    );
    assert_eq!(
        parse(&[6, b'd', b'b']).unwrap().1,
        Command::DropDatabase(b"db")
    );
    assert_eq!(parse(&[7, 0x14]).unwrap().1, Command::Refresh(0x14));
    assert_eq!(parse(&[8]).unwrap().1, Command::Shutdown);
    assert_eq!(parse(&[9]).unwrap().1, Command::Statistics);
    assert_eq!(parse(&[10]).unwrap().1, Command::ProcessInfo);
    assert_eq!(
        parse(&[12, 0x78, 0x56, 0x34, 0x12]).unwrap().1,
        Command::ProcessKill(0x1234_5678)
    );
    assert_eq!(parse(&[13]).unwrap().1, Command::Debug);
    assert_eq!(
        parse(&[19, 2, b'd', b'b']).unwrap().1,
        Command::TableDump(&[2, b'd', b'b'])
    );
    assert_eq!(parse(&[27, 1, 0]).unwrap().1, Command::SetOption(1));
}

#[test]
fn execute_envelope_requires_the_whole_native_header_but_preserves_all_flag_bits() {
    for length in 0..9 {
        let mut command = vec![0x17];
        command.resize(1 + length, 0);
        assert!(parse(&command).is_err());
    }
    for flags in [0, 1, 8, 9, 0xff] {
        let command = [0x17, 7, 0, 0, 0, flags, 9, 8, 7, 6, 0xfe];
        assert_eq!(
            parse(&command).unwrap().1,
            Command::Execute {
                stmt: 7,
                flags,
                params: &[0xfe]
            }
        );
    }
}
