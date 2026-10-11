use super::super::myc::constants::ColumnType;
use super::super::{ParamParser, StatementData, ValueInner};
use crate::{BindErrorPhase, CommandAllocationAdmission, ErrorKind};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

fn admission() -> CommandAllocationAdmission {
    Arc::new(|_| Ok(Arc::new(())))
}

fn legacy<'a>(input: &'a [u8], statement: &'a mut StatementData) -> ParamParser<'a> {
    ParamParser::execute(input, statement, false, 0, None)
}

fn malformed(error: crate::BindError) {
    assert_eq!(error.phase, BindErrorPhase::Framing);
    assert_eq!(error.error_kind(), Some(ErrorKind::ER_MALFORMED_PACKET));
    assert_eq!(error.message(), b"Malformed communication packet.");
    assert_eq!(error.error_kind().unwrap().sqlstate(), b"HY000");
}

#[test]
fn execute_reusing_bound_types_consumes_the_flag_byte() {
    let mut statement = StatementData {
        params: 1,
        ..StatementData::default()
    };

    let first = [0x00, 0x01, ColumnType::MYSQL_TYPE_TINY as u8, 0x00, 12];
    let first_value = legacy(&first, &mut statement)
        .parse()
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(first_value.value.into_inner(), ValueInner::Int(12));

    let second = [0x00, 0x00, 11];
    let second_value = legacy(&second, &mut statement)
        .parse()
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(second_value.value.into_inner(), ValueInner::Int(11));
}

#[test]
fn malformed_execute_parameters_return_errors_instead_of_panicking() {
    let mut statement = StatementData {
        params: 1,
        ..StatementData::default()
    };
    for input in [
        &[][..],
        &[0x00][..],
        &[0x00, 0x00][..],
        &[0x00, 0x01, ColumnType::MYSQL_TYPE_LONG as u8][..],
        &[0x00, 0x01, 0xff, 0x00][..],
    ] {
        assert!(legacy(input, &mut statement).parse().is_err());
    }
}

#[test]
fn internal_temporal_type_frames_raw_bytes_but_fails_native_placeholder_admission() {
    let mut statement = StatementData {
        params: 1,
        ..StatementData::default()
    };
    let input = [
        0x00,
        0x01,
        ColumnType::MYSQL_TYPE_DATETIME2 as u8,
        0x00,
        0x07,
        0xe8,
        0x07,
        0x09,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
    ];
    let mut bindings = legacy(&input, &mut statement).parse_bindings().unwrap();
    assert_eq!(
        bindings.slots()[0].raw_value,
        &[0xe8, 0x07, 0x09, 0x0c, 0x0d, 0x0e, 0x0f]
    );
    let error = bindings
        .bind_placeholders()
        .err()
        .expect("native internal type is not a PS source");
    assert_eq!(error.phase, crate::BindErrorPhase::PlaceholderType);
    assert_eq!(
        error.error_kind(),
        Some(crate::ErrorKind::ER_WRONG_ARGUMENTS)
    );
    assert_eq!(
        error.message(),
        b"Incorrect arguments to mysqld_stmt_execute"
    );
}

#[test]
fn long_data_keeps_its_execute_parameter_type() {
    let mut statement = StatementData {
        params: 1,
        ..StatementData::default()
    };
    statement.long_data.insert(0, b"payload".to_vec());
    let input = [0x00, 0x01, ColumnType::MYSQL_TYPE_BLOB as u8, 0x00];
    let value = legacy(&input, &mut statement)
        .parse()
        .unwrap()
        .pop()
        .unwrap();
    assert!(value.is_long_data);
    assert_eq!(value.coltype, ColumnType::MYSQL_TYPE_BLOB);
    assert_eq!(value.value.into_inner(), ValueInner::Bytes(b"payload"));
}

#[test]
fn binary_float_parameter_preserves_width_and_bits_through_type_reuse() {
    let mut statement = StatementData {
        params: 1,
        ..StatementData::default()
    };
    for (index, bits) in [0_u32, 0x8000_0000, 1, 0x7f7f_ffff, 0x7f80_0000, 0x7fc0_1234]
        .into_iter()
        .enumerate()
    {
        let mut input = vec![0x00, u8::from(index == 0)];
        if index == 0 {
            input.extend_from_slice(&[ColumnType::MYSQL_TYPE_FLOAT as u8, 0]);
        }
        input.extend_from_slice(&bits.to_le_bytes());
        let value = legacy(&input, &mut statement)
            .parse()
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(value.coltype, ColumnType::MYSQL_TYPE_FLOAT);
        assert!(!value.is_long_data);
        let ValueInner::Float(value) = value.value.into_inner() else {
            panic!("binary FLOAT was promoted before the backend PARAM producer");
        };
        assert_eq!(value.to_bits(), bits);
    }
}

#[test]
fn query_types_and_names_are_interleaved_with_exact_order_and_suffix() {
    // N=3/sets=1/nullmap/newtypes; TINY "a", STRING anonymous,
    // unsigned LONGLONG name with invalid UTF8/NUL; then values/SQL.
    let mut input = vec![
        3, 1, 0, 2, 1, 0, 1, b'a', 254, 0, 0, 8, 128, 3, 0xff, 0, b'z',
    ];
    input.push(0xfe);
    input.extend_from_slice(&[3, 0, b'x', 0xff]);
    input.extend_from_slice(&u64::MAX.to_le_bytes());
    input.extend_from_slice(b"SELECT 1; SELECT 2");
    let bindings = ParamParser::query(&input, true, Some(admission()))
        .parse_bindings()
        .unwrap();
    assert_eq!(bindings.placeholder_count(), 0);
    assert!(bindings.has_new_types());
    assert!(bindings.query_attributes());
    assert_eq!(bindings.slots().len(), 3);
    assert_eq!(bindings.slots()[0].name, Some(&b"a"[..]));
    assert_eq!(bindings.slots()[0].raw_value, &[0xfe]);
    assert_eq!(bindings.slots()[1].name, None);
    assert_eq!(bindings.slots()[1].raw_value, &[0, b'x', 0xff]);
    assert_eq!(bindings.slots()[2].name, Some(&[0xff, 0, b'z'][..]));
    assert!(bindings.slots()[2].unsigned);
    assert_eq!(bindings.slots()[2].raw_value, &u64::MAX.to_le_bytes());
    assert_eq!(bindings.suffix(), b"SELECT 1; SELECT 2");
    assert_eq!(bindings.slots()[0].raw_value.as_ptr(), input[17..].as_ptr());
}

#[test]
fn capability_zero_count_single_set_and_legacy_sql_are_distinct_layouts() {
    let input = b"\0\x01SELECT 1";
    let named = ParamParser::query(input, true, Some(admission()))
        .parse_bindings()
        .unwrap();
    assert!(named.slots().is_empty());
    assert_eq!(named.suffix(), b"SELECT 1");
    let legacy = ParamParser::query(input, false, None)
        .parse_bindings()
        .unwrap();
    assert_eq!(legacy.suffix(), input);
    for input in [
        &[0][..],
        &[0, 0][..],
        &[0, 2][..],
        &[1, 1, 0, 0][..],
        &[252][..],
        &[253, 0][..],
        &[254, 0][..],
        &[255][..],
        &[251, 1][..],
    ] {
        malformed(
            ParamParser::query(input, true, Some(admission()))
                .parse_bindings()
                .err()
                .expect("must reject malformed query"),
        );
    }
    assert_eq!(
        ParamParser::query(b"\0\x01SELECT 1", true, None)
            .parse_bindings()
            .err()
            .unwrap()
            .phase,
        BindErrorPhase::Admission
    );
}

#[test]
fn execute_count_has_no_parameter_set_and_bit8_only_controls_zero_placeholders() {
    let mut statement = StatementData::default();
    for flags in [0, 1] {
        let bindings =
            ParamParser::execute(&[255, 99], &mut statement, true, flags, Some(admission()))
                .parse_bindings()
                .unwrap();
        assert_eq!(bindings.execute_flags(), flags);
        assert!(bindings.slots().is_empty());
        assert_eq!(bindings.suffix(), &[255, 99]);
    }
    for flags in [8, 9] {
        let bindings =
            ParamParser::execute(&[0, 99], &mut statement, true, flags, Some(admission()))
                .parse_bindings()
                .unwrap();
        assert_eq!(bindings.execute_flags(), flags);
        assert!(bindings.slots().is_empty());
        assert_eq!(bindings.suffix(), &[99]);
    }
    statement.params = 1;
    let input = [1, 0, 1, 1, 0, 0, 7, 99];
    for flags in [0, 1, 8, 9] {
        let mut bindings =
            ParamParser::execute(&input, &mut statement, true, flags, Some(admission()))
                .parse_bindings()
                .unwrap();
        assert_eq!(bindings.slots()[0].raw_value, &[7]);
        assert_eq!(bindings.suffix(), &[99]); // native Execute ignores trailing bytes
        assert_eq!(
            bindings.bind_placeholders().unwrap()[0].value.into_inner(),
            ValueInner::Int(7)
        );
    }
}

#[test]
fn named_placeholders_and_attributes_do_not_pollute_statement_source_types() {
    let mut statement = StatementData {
        params: 1,
        ..Default::default()
    };
    let input = [2, 0, 1, 1, 0, 1, b'p', 254, 0, 1, b'a', 17, 1, b'x'];
    let mut bindings = ParamParser::execute(&input, &mut statement, true, 8, Some(admission()))
        .parse_bindings()
        .unwrap();
    assert_eq!(bindings.slots().len(), 2);
    assert_eq!(bindings.slots()[0].name, Some(&b"p"[..]));
    assert_eq!(bindings.slots()[1].name, Some(&b"a"[..]));
    assert_eq!(
        bindings.bind_placeholders().unwrap()[0].value.into_inner(),
        ValueInner::Int(17)
    );
    drop(bindings);
    assert_eq!(statement.bound_types, vec![(1, false)]);
    let reuse = [2, 2, 0, 19]; // extra slot NULL -> accepted before missing-type test
    let mut bindings = ParamParser::execute(&reuse, &mut statement, true, 0, Some(admission()))
        .parse_bindings()
        .unwrap();
    assert_eq!(bindings.slots()[0].name, None);
    assert!(bindings.slots()[1].is_null);
    assert_eq!(
        bindings.bind_placeholders().unwrap()[0].value.into_inner(),
        ValueInner::Int(19)
    );
    drop(bindings);
    malformed(
        ParamParser::execute(&[2, 0, 0, 20], &mut statement, true, 8, Some(admission()))
            .parse_bindings()
            .err()
            .unwrap(),
    );
}

#[test]
fn too_few_parameters_are_precheck_errors_only_after_valid_framing() {
    let mut statement = StatementData {
        params: 2,
        ..Default::default()
    };
    let error = ParamParser::execute(
        &[1, 1, 1, 1, 0, 0],
        &mut statement,
        true,
        8,
        Some(admission()),
    )
    .parse_bindings()
    .err()
    .unwrap();
    assert_eq!(error.phase, BindErrorPhase::StatementCount);
    assert_eq!(error.error_kind(), Some(ErrorKind::ER_WRONG_ARGUMENTS));
    assert_eq!(error.message(), b"Incorrect arguments to COM_STMT_EXECUTE");
    assert_eq!(error.error_kind().unwrap().sqlstate(), b"HY000");
    malformed(
        ParamParser::execute(&[1, 0, 1, 1], &mut statement, true, 8, Some(admission()))
            .parse_bindings()
            .err()
            .unwrap(),
    );
}

#[test]
fn fifteen_bit_type_null_first_and_native_invalid_placeholder_setter_are_preserved() {
    let mut statement = StatementData {
        params: 2,
        ..Default::default()
    };
    let input = [2, 3, 1, 1, 0, 0, 1, 1, 0]; // second token=0x0101, both NULL
    let mut bindings = ParamParser::execute(&input, &mut statement, true, 8, Some(admission()))
        .parse_bindings()
        .unwrap();
    assert_eq!(bindings.slots()[1].type_code, 257);
    assert!(bindings.slots()[1].is_null);
    let error = bindings.bind_placeholders().err().unwrap();
    assert_eq!(error.phase, BindErrorPhase::PlaceholderType);
    drop(bindings);
    assert_eq!(statement.bound_types, vec![(1, false), (243, false)]);
    // QUERY NULL BOOL bypasses value validation exactly as the native parser.
    let bindings = ParamParser::query(&[1, 1, 1, 1, 244, 0, 0], true, Some(admission()))
        .parse_bindings()
        .unwrap();
    assert_eq!(bindings.slots()[0].type_code, 244);
    assert!(bindings.slots()[0].is_null);
    malformed(
        ParamParser::query(&[1, 1, 0, 1, 244, 0, 0, 1], true, Some(admission()))
            .parse_bindings()
            .err()
            .unwrap(),
    );
}

#[test]
fn long_data_is_placeholder_only_null_first_and_type_checked() {
    let mut statement = StatementData {
        params: 1,
        ..Default::default()
    };
    statement.long_data.insert(0, b"first".to_vec());
    statement.long_data.insert(1, b"not-an-attribute".to_vec());
    let input = [2, 0, 1, 252, 0, 0, 254, 0, 1, b'a', 1, b'x'];
    let bindings = ParamParser::execute(&input, &mut statement, true, 8, Some(admission()))
        .parse_bindings()
        .unwrap();
    assert!(bindings.slots()[0].is_long_data);
    assert_eq!(bindings.slots()[0].raw_value, b"first");
    assert!(!bindings.slots()[1].is_long_data);
    assert_eq!(bindings.slots()[1].raw_value, b"x");
    drop(bindings);
    malformed(
        legacy(&[0, 1, 3, 0], &mut statement)
            .parse_bindings()
            .err()
            .unwrap(),
    );
    let mut bindings = legacy(&[1, 1, 3, 0], &mut statement)
        .parse_bindings()
        .unwrap();
    assert!(bindings.slots()[0].is_null);
    assert!(!bindings.slots()[0].is_long_data);
    // Framing is NULL first, but native insert_parameters subsequently checks
    // the actual Item LONG_DATA_VALUE state before publishing packet NULL.
    assert_eq!(
        bindings.bind_placeholders().err().unwrap().phase,
        BindErrorPhase::PlaceholderType
    );
    drop(bindings);
    let mut bindings = legacy(&[1, 1, 252, 0], &mut statement)
        .parse_bindings()
        .unwrap();
    assert!(bindings.slots()[0].is_null);
    let values = bindings.bind_placeholders().unwrap();
    assert!(values[0].is_long_data);
    assert_eq!(values[0].value.into_inner(), ValueInner::Bytes(b"first"));
}

#[test]
fn temporal_raw_bytes_and_timezone_displacement_are_not_normalized_by_framing() {
    let mut input = vec![1, 1, 0, 1, 12, 0, 1, b't', 13];
    let temporal = [0xe8, 7, 9, 12, 13, 14, 15, 0, 0, 0, 0, 180, 0];
    input.extend_from_slice(&temporal);
    input.extend_from_slice(b"SELECT 1");
    let bindings = ParamParser::query(&input, true, Some(admission()))
        .parse_bindings()
        .unwrap();
    assert_eq!(bindings.slots()[0].raw_value, &temporal);
    assert_eq!(bindings.suffix(), b"SELECT 1");
}

#[test]
fn native_default_length_clamps_but_decimal_and_temporal_underrun_fail() {
    let input = [1, 1, 0, 1, 254, 0, 0, 100, b'x'];
    let bindings = ParamParser::query(&input, true, Some(admission()))
        .parse_bindings()
        .unwrap();
    assert_eq!(bindings.slots()[0].raw_value, b"x");
    assert!(bindings.suffix().is_empty());
    for code in [0, 7, 10, 11, 12, 246] {
        malformed(
            ParamParser::query(
                &[1, 1, 0, 1, code, 0, 0, 100, b'x'],
                true,
                Some(admission()),
            )
            .parse_bindings()
            .err()
            .unwrap(),
        );
    }
}

#[test]
fn full_framing_precedes_allocation_and_count_65535_has_checked_capacity() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let deny: CommandAllocationAdmission = Arc::new(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        Err(std::io::Error::other("actual budget exhausted"))
    });
    malformed(
        ParamParser::query(&[1, 1, 0, 1, 8, 0, 0], true, Some(deny.clone()))
            .parse_bindings()
            .err()
            .unwrap(),
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let mut input = vec![252, 255, 255, 1];
    input.resize(input.len() + 65535usize.div_ceil(8), 255);
    input.push(1);
    for _ in 0..65535 {
        input.extend_from_slice(&[1, 0, 0]);
    }
    let error = ParamParser::query(&input, true, Some(deny))
        .parse_bindings()
        .err()
        .unwrap();
    assert_eq!(error.phase, BindErrorPhase::Admission);
    assert_eq!(error.error_kind(), None);
    assert_eq!(error.into_io().to_string(), "actual budget exhausted");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let bindings = ParamParser::query(&input, true, Some(admission()))
        .parse_bindings()
        .unwrap();
    assert_eq!(bindings.slots().len(), 65535);
    assert!(bindings
        .slots()
        .iter()
        .all(|slot| slot.is_null && slot.name.is_none()));
    malformed(
        ParamParser::query(&[253, 0, 0, 1, 1], true, Some(admission()))
            .parse_bindings()
            .err()
            .unwrap(),
    ); // 65536
}

#[test]
fn binding_and_placeholder_leases_release_with_their_physical_owners() {
    struct Lease(Arc<AtomicUsize>, usize);
    impl Drop for Lease {
        fn drop(&mut self) {
            self.0.fetch_sub(self.1, Ordering::SeqCst);
        }
    }
    let current = Arc::new(AtomicUsize::new(0));
    let live = current.clone();
    let permit: CommandAllocationAdmission = Arc::new(move |bytes| {
        live.fetch_add(bytes, Ordering::SeqCst);
        Ok(Arc::new(Lease(live.clone(), bytes)))
    });
    let mut statement = StatementData {
        params: 1,
        ..Default::default()
    };
    let input = [1, 0, 1, 1, 0, 0, 7];
    let mut bindings = ParamParser::execute(&input, &mut statement, true, 8, Some(permit))
        .parse_bindings()
        .unwrap();
    let slot_bytes = std::mem::size_of::<crate::RawParamValue<'_>>();
    assert_eq!(current.load(Ordering::SeqCst), slot_bytes);
    let values = bindings.bind_placeholders().unwrap();
    let value_bytes = std::mem::size_of::<crate::ParamValue<'_>>();
    let type_bytes = std::mem::size_of::<(u16, bool)>();
    assert_eq!(
        current.load(Ordering::SeqCst),
        slot_bytes + value_bytes + type_bytes
    );
    assert_eq!(values[0].value.into_inner(), ValueInner::Int(7));
    drop(bindings);
    assert_eq!(current.load(Ordering::SeqCst), value_bytes + type_bytes);
    drop(values);
    assert_eq!(current.load(Ordering::SeqCst), type_bytes);
    drop(statement);
    assert_eq!(current.load(Ordering::SeqCst), 0);
}

#[test]
fn fixed_length_callers_use_low_uint32_not_the_ll_helper_and_distinguish_fb_ff() {
    for prefix in [254, 255] {
        // count=0 with ignored high half; sets=1 with ignored high half.
        let input = [
            prefix, 0, 0, 0, 0, 255, 255, 255, 255, prefix, 1, 0, 0, 0, 255, 255, 255, 255, b'S',
        ];
        let bindings = ParamParser::query(&input, true, Some(admission()))
            .parse_bindings()
            .unwrap();
        assert!(bindings.slots().is_empty());
        assert_eq!(bindings.suffix(), b"S");
    }
    let input = [
        1, 1, 0, 1, 254, 0, 0, 254, 1, 0, 0, 0, 255, 255, 255, 255, b'x',
    ];
    let bindings = ParamParser::query(&input, true, Some(admission()))
        .parse_bindings()
        .unwrap();
    assert_eq!(bindings.slots()[0].raw_value, b"x");
    let input = [1, 1, 0, 1, 254, 0, 0, 251, b'x']; // FB raw length=251, clipped default
    let bindings = ParamParser::query(&input, true, Some(admission()))
        .parse_bindings()
        .unwrap();
    assert_eq!(bindings.slots()[0].raw_value, b"x");
    malformed(
        ParamParser::query(&[1, 1, 0, 1, 254, 0, 0, 255], true, Some(admission()))
            .parse_bindings()
            .err()
            .unwrap(),
    );
    // Metadata FB is NULL_LENGTH and cannot name a bounded packet slice.
    malformed(
        ParamParser::query(&[1, 1, 0, 1, 254, 0, 251], true, Some(admission()))
            .parse_bindings()
            .err()
            .unwrap(),
    );
}

#[test]
fn leased_decoded_bindings_cannot_escape_through_the_legacy_unleased_vector() {
    let bindings = ParamParser::query(b"SELECT 1", false, Some(admission()))
        .parse_bindings()
        .unwrap();
    let error = ParamParser::decoded(bindings).parse().err().unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert_eq!(
        error.to_string(),
        "admitted bindings require their retained collection owner"
    );
}

#[test]
fn every_truncated_named_query_prefix_is_a_fallible_packet_error_before_admission() {
    // Every byte before payload completion is mandatory; after completion the
    // remainder is SQL, not part of the parameter packet.
    let input = [1, 1, 0, 1, 8, 128, 2, 0xff, 0, 1, 2, 3, 4, 5, 6, 7, 8];
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let issuer: CommandAllocationAdmission = Arc::new(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(()))
    });
    for end in 0..input.len() {
        malformed(
            ParamParser::query(&input[..end], true, Some(issuer.clone()))
                .parse_bindings()
                .err()
                .unwrap(),
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let bindings = ParamParser::query(&input, true, Some(issuer))
        .parse_bindings()
        .unwrap();
    assert_eq!(bindings.slots()[0].name, Some(&[0xff, 0][..]));
    assert_eq!(bindings.slots()[0].type_code, 8);
    assert!(bindings.slots()[0].unsigned);
    assert_eq!(bindings.slots()[0].raw_value, &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn native_source_type_issuer_keeps_int24_not_year_and_null_reuse_keeps_invalid_source() {
    for code in 0u16..=512 {
        let mut statement = StatementData {
            params: 1,
            ..Default::default()
        };
        let token = code.to_le_bytes();
        let input = [1, 1, token[0], token[1]];
        let mut bindings = legacy(&input, &mut statement).parse_bindings().unwrap();
        let result = bindings.bind_placeholders();
        let accepted = matches!(code, 0..=12 | 15 | 245 | 246 | 249..=254);
        if accepted {
            let values = result.unwrap();
            assert!(values[0].value.is_null(), "code={code}");
            assert_eq!(values[0].coltype as u16, code);
        } else {
            assert_eq!(
                result.err().unwrap().phase,
                BindErrorPhase::PlaceholderType,
                "code={code}"
            );
        }
        drop(bindings);
        assert_eq!(
            statement.bound_types,
            vec![(if accepted { code } else { 243 }, false)]
        );
        let mut reuse = legacy(&[1, 0], &mut statement).parse_bindings().unwrap();
        let values = reuse.bind_placeholders().unwrap();
        assert!(values[0].value.is_null());
        assert_eq!(values[0].coltype as u16, if accepted { code } else { 243 });
    }
    let mut statement = StatementData {
        params: 1,
        ..Default::default()
    };
    let mut reuse_null = legacy(&[1, 0], &mut statement).parse_bindings().unwrap();
    assert_eq!(
        reuse_null.bind_placeholders().unwrap()[0].coltype,
        ColumnType::MYSQL_TYPE_UNKNOWN
    );
    drop(reuse_null);
    for code in [6, 9] {
        let input = [0, 1, code, 0, 0];
        let mut bindings = legacy(&input, &mut statement).parse_bindings().unwrap();
        assert_eq!(
            bindings.bind_placeholders().err().unwrap().phase,
            BindErrorPhase::PlaceholderType
        );
        drop(bindings);
        assert_eq!(statement.bound_types, vec![(u16::from(code), false)]);
    }
}

#[test]
fn signed_unsigned_integer_carriers_use_actual_width_without_losing_raw_bits() {
    for (code, width) in [(1u8, 1usize), (2, 2), (3, 4), (8, 8)] {
        for unsigned in [false, true] {
            for bits in [0u64, 1, u64::MAX, 1u64 << (width * 8 - 1)] {
                let mut input = vec![0, 1, code, u8::from(unsigned) << 7];
                let bytes = bits.to_le_bytes();
                input.extend_from_slice(&bytes[..width]);
                let mut statement = StatementData {
                    params: 1,
                    ..Default::default()
                };
                let mut bindings = legacy(&input, &mut statement).parse_bindings().unwrap();
                assert_eq!(bindings.slots()[0].raw_value, &bytes[..width]);
                let values = bindings.bind_placeholders().unwrap();
                assert_eq!(values[0].coltype as u8, code);
                let shift = 64 - width * 8;
                let expected = if unsigned {
                    ValueInner::UInt(bits << shift >> shift)
                } else {
                    ValueInner::Int(((bits << shift) as i64) >> shift)
                };
                assert_eq!(values[0].value.into_inner(), expected);
            }
        }
    }
}
