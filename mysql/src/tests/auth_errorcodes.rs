use crate::errorcodes::ErrorKind;

#[test]
fn legacy_and_mysql_8_password_errors_keep_distinct_wire_codes() {
    for (number, expected) in [
        (1699, ErrorKind::ER_SET_PASSWORD_AUTH_PLUGIN),
        (4102, ErrorKind::ER_SET_PASSWORD_AUTH_PLUGIN_ERROR),
        (3638, ErrorKind::ER_CREDENTIALS_CONTRADICT_TO_HISTORY),
        (3639, ErrorKind::ER_WARNING_PASSWORD_HISTORY_CLAUSES_VOID),
        (
            13294,
            ErrorKind::ER_WARNING_RETAIN_CURRENT_PASSWORD_CLAUSE_VOID,
        ),
        (
            13295,
            ErrorKind::ER_WARNING_DISCARD_OLD_PASSWORD_CLAUSE_VOID,
        ),
        (3891, ErrorKind::ER_INCORRECT_CURRENT_PASSWORD),
        (3892, ErrorKind::ER_MISSING_CURRENT_PASSWORD),
        (3893, ErrorKind::ER_CURRENT_PASSWORD_NOT_REQUIRED),
    ] {
        let error = ErrorKind::from(number);
        assert_eq!(error, expected);
        assert_eq!(error as u16, number);
        assert_eq!(error.sqlstate(), b"HY000");
    }
}
