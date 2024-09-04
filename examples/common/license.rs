use cipherstash_dynamodb::{Decryptable, Encryptable, Identifiable, Searchable};

#[derive(Debug, Identifiable, Encryptable, Decryptable, Searchable)]
pub struct License {
    #[partition_key]
    email: String,
    number: String,
    expires: String,
    #[allow(dead_code)]
    #[cipherstash(skip)]
    reviewed_at: Option<String>,
}

impl License {
    #[allow(dead_code)]
    pub fn new(
        email: impl Into<String>,
        number: impl Into<String>,
        expires: impl Into<String>,
    ) -> Self {
        Self {
            email: email.into(),
            number: number.into(),
            expires: expires.into(),
            reviewed_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipherstash_typename() {
        assert_eq!(License::type_name(), "license");
    }
}
