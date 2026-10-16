#[test]
fn system_gap_uses_the_existing_native_timestamp_warning_kind_not_a_new_wire_number() {
    use crate::errorcodes::ErrorKind;
    let kind = ErrorKind::ER_WARN_INVALID_TIMESTAMP;
    assert_eq!(kind as u16, 1299);
    assert_eq!(ErrorKind::from_code(1299), Some(kind));
    assert_eq!(kind.sqlstate(), b"HY000");
    assert_ne!(ErrorKind::from_code(1292), Some(kind));
}

use crate::errorcodes::ErrorKind;

#[test]
fn persist_missing_record_and_static_privilege_have_distinct_native_packets() {
    for (number, kind, state) in [
        (3615, ErrorKind::ER_VAR_DOES_NOT_EXIST, b"HY000"),
        (
            3630,
            ErrorKind::ER_PERSIST_ONLY_ACCESS_DENIED_ERROR,
            b"42000",
        ),
    ] {
        assert_eq!(kind as u16, number);
        assert_eq!(ErrorKind::from_code(number), Some(kind));
        assert_eq!(ErrorKind::from(number), kind);
        assert_eq!(kind.sqlstate(), state);
    }
    assert_ne!(
        ErrorKind::ER_PERSIST_ONLY_ACCESS_DENIED_ERROR,
        ErrorKind::ER_SPECIFIC_ACCESS_DENIED_ERROR
    );
    assert_eq!(ErrorKind::from_code(u16::MAX), None);
}

#[test]
fn user_defined_collation_warning_has_a_distinct_native_number_and_state() {
    let kind = ErrorKind::ER_WARN_DEPRECATED_USER_DEFINED_COLLATIONS;
    assert_eq!(kind as u16, 4162);
    assert_eq!(ErrorKind::from_code(4162), Some(kind));
    assert_eq!(ErrorKind::from(4162), kind);
    assert_eq!(kind.sqlstate(), b"HY000");
    assert_ne!(kind, ErrorKind::ER_WARN_DEPRECATED_COLLATION);
    assert_ne!(kind, ErrorKind::ER_WARN_DEPRECATED_UTF8MB3_COLLATION);
    assert_eq!(ErrorKind::from_code(u16::MAX), None);
}

#[test]
fn deprecated_non_utf8mb3_collation_keeps_its_distinct_native_identity() {
    let kind = ErrorKind::ER_WARN_DEPRECATED_COLLATION;
    assert_eq!(kind as u16, 4079);
    assert_eq!(ErrorKind::from_code(4079), Some(kind));
    assert_eq!(ErrorKind::from(4079), kind);
    assert_eq!(kind.sqlstate(), b"HY000");
    for (number, other) in [
        (3778, ErrorKind::ER_WARN_DEPRECATED_UTF8MB3_COLLATION),
        (3719, ErrorKind::ER_WARN_DEPRECATED_UTF8_ALIAS),
        (1287, ErrorKind::ER_WARN_DEPRECATED_SYNTAX),
    ] {
        assert_eq!(other as u16, number);
        assert_eq!(ErrorKind::from_code(number), Some(other));
        assert_ne!(kind, other);
    }
    assert_eq!(ErrorKind::from_code(u16::MAX), None);
}

#[test]
fn schema_read_only_is_not_global_or_transaction_read_only() {
    assert_eq!(ErrorKind::ER_SCHEMA_READ_ONLY as u16, 3989);
    assert_eq!(
        ErrorKind::from_code(3989),
        Some(ErrorKind::ER_SCHEMA_READ_ONLY)
    );
    assert_eq!(ErrorKind::from(3989), ErrorKind::ER_SCHEMA_READ_ONLY);
    assert_eq!(ErrorKind::ER_SCHEMA_READ_ONLY.sqlstate(), b"HY000");
    assert_eq!(ErrorKind::from_code(3503), Some(ErrorKind::ER_NO_SUCH_DB));
    assert_eq!(ErrorKind::ER_NO_SUCH_DB.sqlstate(), b"42Y07");
    assert_eq!(
        ErrorKind::from_code(3552),
        Some(ErrorKind::ER_NO_SYSTEM_SCHEMA_ACCESS)
    );
    assert_eq!(ErrorKind::ER_NO_SYSTEM_SCHEMA_ACCESS.sqlstate(), b"HY000");
    assert_eq!(ErrorKind::ER_BAD_DB_ERROR as u16, 1049);
    assert_eq!(
        ErrorKind::from_code(1302),
        Some(ErrorKind::ER_CONFLICTING_DECLARATIONS)
    );
    assert_ne!(
        ErrorKind::ER_SCHEMA_READ_ONLY,
        ErrorKind::ER_OPTION_PREVENTS_STATEMENT
    );
    assert_ne!(
        ErrorKind::ER_SCHEMA_READ_ONLY,
        ErrorKind::ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION
    );
}

#[test]
fn drop_parent_and_delete_row_remain_distinct_native_conditions() {
    let kind = ErrorKind::ER_FK_CANNOT_DROP_PARENT;
    assert_eq!(kind as u16, 3730);
    assert_eq!(ErrorKind::from_code(3730), Some(kind));
    assert_eq!(ErrorKind::from(3730), kind);
    assert_eq!(kind.sqlstate(), b"HY000");
    assert_eq!(ErrorKind::ER_ROW_IS_REFERENCED_2 as u16, 1451);
    assert_eq!(ErrorKind::ER_ROW_IS_REFERENCED_2.sqlstate(), b"23000");
    assert_eq!(ErrorKind::from_code(u16::MAX), None);
}

#[test]
fn account_note_conditions_keep_their_native_number_and_state() {
    for (number, kind) in [
        (3162, ErrorKind::ER_USER_DOES_NOT_EXIST),
        (3163, ErrorKind::ER_USER_ALREADY_EXISTS),
    ] {
        assert_eq!(kind as u16, number);
        assert_eq!(ErrorKind::from_code(number), Some(kind));
        assert_eq!(ErrorKind::from(number), kind);
        assert_eq!(kind.sqlstate(), b"HY000");
    }
    assert_eq!(ErrorKind::from_code(u16::MAX), None);
}

#[test]
fn network_and_secure_transport_native_errors_keep_number_and_state() {
    for (number, kind) in [
        (3130, ErrorKind::ER_PLUGGABLE_PROTOCOL_COMMAND_NOT_SUPPORTED),
        (3159, ErrorKind::ER_SECURE_TRANSPORT_REQUIRED),
        (3160, ErrorKind::ER_NO_SECURE_TRANSPORTS_CONFIGURED),
    ] {
        assert_eq!(ErrorKind::from(number), kind);
        assert_eq!(kind as u16, number);
        assert_eq!(kind.sqlstate(), b"HY000");
    }
}

#[test]
fn functional_index_conditions_round_trip_with_their_actual_native_sqlstate() {
    for (number, kind, state) in [
        (
            3751,
            ErrorKind::ER_WARN_DATA_TRUNCATED_FUNCTIONAL_INDEX,
            b"01000",
        ),
        (
            3752,
            ErrorKind::ER_WARN_DATA_OUT_OF_RANGE_FUNCTIONAL_INDEX,
            b"22003",
        ),
        (
            3754,
            ErrorKind::ER_FUNCTIONAL_INDEX_REF_AUTO_INCREMENT,
            b"HY000",
        ),
        (
            3800,
            ErrorKind::ER_FUNCTIONAL_INDEX_ROW_VALUE_IS_NOT_ALLOWED,
            b"HY000",
        ),
        (
            3907,
            ErrorKind::ER_FUNCTIONAL_INDEX_DATA_IS_TOO_LONG,
            b"22001",
        ),
    ] {
        assert_eq!(kind as u16, number);
        assert_eq!(ErrorKind::from_code(number), Some(kind));
        assert_eq!(kind.sqlstate(), state);
    }
}

#[test]
fn aes_native_error_numbers_and_states_round_trip() {
    for (code, kind, state) in [
        (1582, ErrorKind::ER_WRONG_PARAMCOUNT_TO_NATIVE_FCT, b"42000"),
        (1618, ErrorKind::WARN_OPTION_IGNORED, b"HY000"),
        (1882, ErrorKind::ER_AES_INVALID_IV, b"HY000"),
        (3235, ErrorKind::ER_AES_INVALID_KDF_NAME, b"HY000"),
        (3236, ErrorKind::ER_AES_INVALID_KDF_ITERATIONS, b"HY000"),
        (3237, ErrorKind::WARN_AES_KEY_SIZE, b"HY000"),
        (3238, ErrorKind::ER_AES_INVALID_KDF_OPTION_SIZE, b"HY000"),
    ] {
        assert_eq!(kind as u16, code);
        assert_eq!(ErrorKind::from_code(code), Some(kind));
        assert_eq!(kind.sqlstate(), state);
    }
}

#[test]
fn optional_native_lookup_preserves_the_single_mapping_and_unknown_numbers() {
    let mut known = 0;
    for number in 0..=u16::MAX {
        if let Some(kind) = ErrorKind::from_code(number) {
            assert_eq!(kind as u16, number);
            assert_eq!(ErrorKind::from(number), kind);
            known += 1;
        }
    }
    assert!(known > 900, "the native mapping must not be narrowed");
    for number in [0, 4321, 30_001, u16::MAX] {
        assert_eq!(ErrorKind::from_code(number), None, "{number}");
    }
}

#[test]
fn json_error_identities_round_trip_with_mysql_sqlstate() {
    for (number, state) in [
        (3090, b"HY000"),
        (3135, b"HY000"),
        (3004, b"0Z002"),
        (3064, b"HY000"),
        (3141, b"22032"),
        (3143, b"42000"),
        (3144, b"22032"),
        (3146, b"22032"),
        (3149, b"42000"),
        (3153, b"42000"),
        (3154, b"42000"),
        (3155, b"22003"),
        (3156, b"22018"),
        (3157, b"22032"),
        (3158, b"22032"),
        (3530, b"HY000"),
    ] {
        let error = ErrorKind::from(number);
        assert_eq!(error as u16, number);
        assert_eq!(error.sqlstate(), state);
    }
}

#[test]
fn json_schema_error_kinds_round_trip_without_collapsing_check_violation() {
    for (number, kind, state) in [
        (3853, ErrorKind::ER_INVALID_JSON_TYPE, b"22032"),
        (
            3934,
            ErrorKind::ER_JSON_SCHEMA_VALIDATION_ERROR_WITH_DETAILED_REPORT,
            b"HY000",
        ),
        (3819, ErrorKind::ER_CHECK_CONSTRAINT_VIOLATED, b"HY000"),
    ] {
        assert_eq!(kind as u16, number);
        assert_eq!(ErrorKind::from_code(number), Some(kind));
        assert_eq!(ErrorKind::from(number), kind);
        assert_eq!(kind.sqlstate(), state);
    }
    // Missing/unknown numbers still have no invented built-in identity.
    assert_eq!(ErrorKind::from_code(4321), None);
}

#[test]
fn deprecated_utf8mb3_warning_has_mysql_8046_identity() {
    let alias = ErrorKind::from(3719);
    assert_eq!(alias, ErrorKind::ER_WARN_DEPRECATED_UTF8_ALIAS);
    assert_eq!(alias as u16, 3719);
    let error = ErrorKind::from(3720);
    assert_eq!(error, ErrorKind::ER_WARN_DEPRECATED_UTF8MB3);
    assert_eq!(error as u16, 3720);
}

#[test]
fn invalid_logarithm_argument_uses_data_exception_sqlstate() {
    let error = ErrorKind::from(3020);
    assert_eq!(error, ErrorKind::ER_INVALID_ARGUMENT_FOR_LOGARITHM);
    assert_eq!(error.sqlstate(), b"2201E");
}

#[test]
fn xa_temporary_table_restriction_round_trips_the_native_wire_identity() {
    let error = ErrorKind::from(4091);
    assert_eq!(error, ErrorKind::ER_XA_TEMP_TABLE);
    assert_eq!(error as u16, 4091);
    assert_eq!(error.sqlstate(), b"HY000");
}

#[test]
fn trigger_order_reference_and_if_not_exists_errors_round_trip_native_identities() {
    for (code, expected) in [
        (3011, ErrorKind::ER_REFERENCED_TRG_DOES_NOT_EXIST),
        (
            4100,
            ErrorKind::ER_IF_NOT_EXISTS_UNSUPPORTED_TRG_EXISTS_ON_DIFFERENT_TABLE,
        ),
    ] {
        let error = ErrorKind::from(code);
        assert_eq!(error, expected);
        assert_eq!(error as u16, code);
        assert_eq!(error.sqlstate(), b"HY000");
    }
}
#[test]
fn json_table_geometry_and_delimiter_identities_round_trip_native_code_and_sqlstate() {
    for (code, kind, state) in [
        (3665, ErrorKind::ER_MISSING_JSON_TABLE_VALUE, b"22035"),
        (3666, ErrorKind::ER_WRONG_JSON_TABLE_VALUE, b"2203F"),
        (3669, ErrorKind::ER_JT_VALUE_OUT_OF_RANGE, b"22003"),
        (3670, ErrorKind::ER_JT_MAX_NESTED_PATH, b"42000"),
        (1067, ErrorKind::ER_INVALID_DEFAULT, b"42000"),
        (3923, ErrorKind::ER_WRONG_COMPRESSION_LEVEL_CLIENT, b"HY000"),
        (1416, ErrorKind::ER_CANT_CREATE_GEOMETRY_OBJECT, b"22003"),
        (
            4095,
            ErrorKind::ER_WARN_DEPRECATED_DATETIME_DELIMITER,
            b"HY000",
        ),
        (
            4096,
            ErrorKind::ER_WARN_DEPRECATED_SUPERFLUOUS_DELIMITER,
            b"HY000",
        ),
    ] {
        assert_eq!(ErrorKind::from(code), kind);
        assert_eq!(kind as u16, code);
        assert_eq!(kind.sqlstate(), state);
    }
}

#[test]
fn enumeration_count_and_character_width_have_distinct_native_packets() {
    for (number, kind) in [
        (3504, ErrorKind::ER_TOO_BIG_ENUM),
        (3505, ErrorKind::ER_TOO_LONG_SET_ENUM_VALUE),
    ] {
        assert_eq!(kind as u16, number);
        assert_eq!(ErrorKind::from_code(number), Some(kind));
        assert_eq!(ErrorKind::from(number), kind);
        assert_eq!(kind.sqlstate(), b"HY000");
    }
    assert_ne!(
        ErrorKind::ER_TOO_BIG_ENUM,
        ErrorKind::ER_TOO_LONG_SET_ENUM_VALUE
    );
}
#[test]
fn engine_attribute_native_numbers_keep_distinct_hy000_mappings_and_depth_keeps22032() {
    for (kind, number) in [
        (
            crate::errorcodes::ErrorKind::ER_INVALID_JSON_ATTRIBUTE,
            3980,
        ),
        (
            crate::errorcodes::ErrorKind::ER_ENGINE_ATTRIBUTE_NOT_SUPPORTED,
            3981,
        ),
    ] {
        assert_eq!(kind as u16, number);
        assert_eq!(crate::errorcodes::ErrorKind::from_code(number), Some(kind));
        assert_eq!(crate::errorcodes::ErrorKind::from(number), kind);
        assert_eq!(kind.sqlstate(), b"HY000");
    }
    assert_eq!(
        crate::errorcodes::ErrorKind::ER_JSON_DOCUMENT_TOO_DEEP.sqlstate(),
        b"22032"
    );
    assert_eq!(
        crate::errorcodes::ErrorKind::ER_INVALID_JSON_TEXT.sqlstate(),
        b"22032"
    );
    assert_eq!(crate::errorcodes::ErrorKind::from_code(u16::MAX), None);
}
#[test]
fn derived_hint_native_warning_kinds_roundtrip_without_changing_existing_numbers() {
    for (number, kind) in [
        (3126, ErrorKind::ER_WARN_CONFLICTING_HINT),
        (3127, ErrorKind::ER_WARN_UNKNOWN_QB_NAME),
        (3128, ErrorKind::ER_UNRESOLVED_HINT_NAME),
    ] {
        assert_eq!(kind as u16, number);
        assert_eq!(ErrorKind::from_code(number), Some(kind));
        assert_eq!(ErrorKind::from(number), kind);
        assert_eq!(kind.sqlstate(), b"HY000");
    }
    assert_eq!(ErrorKind::from_code(u16::MAX), None);
}

#[test]
fn invalid_json_column_and_function_argument_text_keep_distinct_native_roundtrips() {
    for (number, kind) in [
        (3140, ErrorKind::ER_INVALID_JSON_TEXT),
        (3141, ErrorKind::ER_INVALID_JSON_TEXT_IN_PARAM),
    ] {
        assert_eq!(kind as u16, number);
        assert_eq!(ErrorKind::from_code(number), Some(kind));
        assert_eq!(ErrorKind::from(number), kind);
        assert_eq!(kind.sqlstate(), b"22032");
    }
    assert_ne!(
        ErrorKind::ER_INVALID_JSON_TEXT,
        ErrorKind::ER_INVALID_JSON_TEXT_IN_PARAM
    );
}
#[test]
fn mfa_and_functional_json_errors_keep_native_identity_and_state() {
    let mfa = [
        ErrorKind::ER_INVALID_MFA_PLUGIN_SPECIFIED,
        ErrorKind::ER_IDENTIFIED_BY_UNSUPPORTED,
        ErrorKind::ER_INVALID_PLUGIN_FOR_REGISTRATION,
        ErrorKind::ER_PLUGIN_REQUIRES_REGISTRATION,
        ErrorKind::ER_MFA_METHOD_EXISTS,
        ErrorKind::ER_MFA_METHOD_NOT_EXISTS,
        ErrorKind::ER_AUTHENTICATION_POLICY_MISMATCH,
        ErrorKind::ER_PLUGIN_REGISTRATION_DONE,
        ErrorKind::ER_INVALID_USER_FOR_REGISTRATION,
        ErrorKind::ER_USER_REGISTRATION_FAILED,
        ErrorKind::ER_MFA_METHODS_INVALID_ORDER,
        ErrorKind::ER_MFA_METHODS_IDENTICAL,
        ErrorKind::ER_INVALID_MFA_OPERATIONS_FOR_PASSWORDLESS_USER,
    ];
    for (offset, kind) in mfa.into_iter().enumerate() {
        let number = 4052 + offset as u16;
        assert_eq!(kind as u16, number);
        assert_eq!(ErrorKind::from_code(number), Some(kind));
        assert_eq!(ErrorKind::from(number), kind);
        assert_eq!(kind.sqlstate(), b"HY000");
    }
    for (kind, number, state) in [
        (
            ErrorKind::ER_INVALID_JSON_VALUE_FOR_FUNC_INDEX,
            3903,
            b"22018",
        ),
        (
            ErrorKind::ER_JSON_VALUE_OUT_OF_RANGE_FOR_FUNC_INDEX,
            3904,
            b"22003",
        ),
        (ErrorKind::ER_WRONG_MVI_VALUE, 3908, b"HY000"),
    ] {
        assert_eq!(kind as u16, number);
        assert_eq!(ErrorKind::from_code(number), Some(kind));
        assert_eq!(kind.sqlstate(), state);
    }
    assert_eq!(
        ErrorKind::from_code(3140),
        Some(ErrorKind::ER_INVALID_JSON_TEXT)
    );
    assert_eq!(
        ErrorKind::from_code(3126),
        Some(ErrorKind::ER_WARN_CONFLICTING_HINT)
    );
    assert_eq!(
        ErrorKind::from_code(3127),
        Some(ErrorKind::ER_WARN_UNKNOWN_QB_NAME)
    );
}
