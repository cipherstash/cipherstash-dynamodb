use super::Plaintext;

impl From<String> for Plaintext {
    fn from(value: String) -> Self {
        Plaintext::Utf8Str(Some(value))
    }
}

impl From<&str> for Plaintext {
    fn from(value: &str) -> Self {
        Plaintext::Utf8Str(Some(value.to_string()))
    }
}

impl From<bool> for Plaintext {
    fn from(value: bool) -> Self {
        Plaintext::Boolean(Some(value))
    }
}

impl From<i64> for Plaintext {
    fn from(value: i64) -> Self {
        Plaintext::BigInt(Some(value))
    }
}

impl From<i32> for Plaintext {
    fn from(value: i32) -> Self {
        Plaintext::Int(Some(value))
    }
}

impl From<i16> for Plaintext {
    fn from(value: i16) -> Self {
        Plaintext::SmallInt(Some(value))
    }
}
