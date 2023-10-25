use super::Plaintext;
use crate::encryption::errors::TypeParseError;

impl TryFrom<&Plaintext> for String {
    type Error = TypeParseError;

    fn try_from(value: &Plaintext) -> Result<Self, Self::Error> {
        match value {
            Plaintext::Utf8Str(Some(s)) => Ok(s.to_string()),
            Plaintext::Utf8Str(None) => Ok("".to_string()),
            _ => Err(TypeParseError("Cannot convert type to String".to_string())),
        }
    }
}
