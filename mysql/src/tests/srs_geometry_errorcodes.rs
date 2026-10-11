use crate::ErrorKind;

#[test]
fn mysql_8046_srs_and_geometry_error_identities_round_trip() {
    for (code, kind, sqlstate) in [
        (3033, ErrorKind::ER_GIS_DIFFERENT_SRIDS, b"HY000"),
        (3035, ErrorKind::ER_GIS_UNKNOWN_ERROR, b"HY000"),
        (3037, ErrorKind::ER_GIS_INVALID_DATA, b"22023"),
        (
            3134,
            ErrorKind::ER_GIS_MAX_POINTS_IN_GEOMETRY_OVERFLOWED,
            b"HY000",
        ),
        (3516, ErrorKind::ER_UNEXPECTED_GEOMETRY_TYPE, b"22S01"),
        (3517, ErrorKind::ER_SRS_PARSE_ERROR, b"SR002"),
        (3519, ErrorKind::ER_WARN_SRS_NOT_FOUND, b"01000"),
        (3520, ErrorKind::ER_SRS_NOT_CARTESIAN, b"22S00"),
        (3521, ErrorKind::ER_SRS_NOT_CARTESIAN_UNDEFINED, b"SR001"),
        (3548, ErrorKind::ER_SRS_NOT_FOUND, b"SR001"),
        (
            3618,
            ErrorKind::ER_NOT_IMPLEMENTED_FOR_GEOGRAPHIC_SRS,
            b"22S00",
        ),
        (3643, ErrorKind::ER_WRONG_SRID_FOR_COLUMN, b"HY000"),
        (
            3704,
            ErrorKind::ER_NOT_IMPLEMENTED_FOR_CARTESIAN_SRS,
            b"22S00",
        ),
        (
            3705,
            ErrorKind::ER_NOT_IMPLEMENTED_FOR_PROJECTED_SRS,
            b"22S00",
        ),
        (
            3743,
            ErrorKind::ER_TRANSFORM_SOURCE_SRS_MISSING_TOWGS84,
            b"22S00",
        ),
        (
            3744,
            ErrorKind::ER_TRANSFORM_TARGET_SRS_MISSING_TOWGS84,
            b"22S00",
        ),
        (
            3708,
            ErrorKind::ER_SRS_MISSING_MANDATORY_ATTRIBUTE,
            b"SR006",
        ),
        (
            3709,
            ErrorKind::ER_SRS_MULTIPLE_ATTRIBUTE_DEFINITIONS,
            b"SR006",
        ),
        (
            3710,
            ErrorKind::ER_SRS_NAME_CANT_BE_EMPTY_OR_WHITESPACE,
            b"SR006",
        ),
        (
            3711,
            ErrorKind::ER_SRS_ORGANIZATION_CANT_BE_EMPTY_OR_WHITESPACE,
            b"SR006",
        ),
        (3712, ErrorKind::ER_SRS_ID_ALREADY_EXISTS, b"SR004"),
        (3713, ErrorKind::ER_WARN_SRS_ID_ALREADY_EXISTS, b"01S00"),
        (3714, ErrorKind::ER_CANT_MODIFY_SRID_0, b"SR000"),
        (3715, ErrorKind::ER_WARN_RESERVED_SRID_RANGE, b"01S01"),
        (3716, ErrorKind::ER_CANT_MODIFY_SRS_USED_BY_COLUMN, b"SR005"),
        (
            3717,
            ErrorKind::ER_SRS_INVALID_CHARACTER_IN_ATTRIBUTE,
            b"SR006",
        ),
        (3718, ErrorKind::ER_SRS_ATTRIBUTE_STRING_TOO_LONG, b"SR006"),
        (3726, ErrorKind::ER_SRS_NOT_GEOGRAPHIC, b"22S00"),
        (
            3731,
            ErrorKind::ER_GEOMETRY_PARAM_LONGITUDE_OUT_OF_RANGE,
            b"22S02",
        ),
        (
            3732,
            ErrorKind::ER_GEOMETRY_PARAM_LATITUDE_OUT_OF_RANGE,
            b"22S03",
        ),
        (3736, ErrorKind::ER_SRS_GEOGCS_INVALID_AXES, b"SR002"),
        (3737, ErrorKind::ER_SRS_INVALID_SEMI_MAJOR_AXIS, b"SR002"),
        (3738, ErrorKind::ER_SRS_INVALID_INVERSE_FLATTENING, b"SR002"),
        (3739, ErrorKind::ER_SRS_INVALID_ANGULAR_UNIT, b"SR002"),
        (3740, ErrorKind::ER_SRS_INVALID_PRIME_MERIDIAN, b"SR002"),
        (
            3741,
            ErrorKind::ER_TRANSFORM_SOURCE_SRS_NOT_SUPPORTED,
            b"22S00",
        ),
        (
            3742,
            ErrorKind::ER_TRANSFORM_TARGET_SRS_NOT_SUPPORTED,
            b"22S00",
        ),
        (4105, ErrorKind::ER_SRS_INVALID_LATITUDE_OF_ORIGIN, b"SR002"),
        (
            4106,
            ErrorKind::ER_SRS_INVALID_LONGITUDE_OF_ORIGIN,
            b"SR002",
        ),
        (
            4107,
            ErrorKind::ER_SRS_UNUSED_PROJ_PARAMETER_PRESENT,
            b"SR002",
        ),
        (4124, ErrorKind::ER_SRS_INVALID_HEIGHT, b"SR002"),
        (4125, ErrorKind::ER_SRS_INVALID_SCALING, b"SR002"),
        (4126, ErrorKind::ER_SRS_INVALID_ZONE_WIDTH, b"SR002"),
        (
            4127,
            ErrorKind::ER_SRS_INVALID_LATITUDE_POLAR_STERE_VAR_A,
            b"SR002",
        ),
    ] {
        assert_eq!(ErrorKind::from(code), kind);
        assert_eq!(kind as u16, code);
        assert_eq!(kind.sqlstate(), sqlstate);
    }
}
