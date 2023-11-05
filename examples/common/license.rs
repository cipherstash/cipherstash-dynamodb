use cryptonamo::{Encryptable, Decryptable, Searchable};

#[derive(Debug, Encryptable)]
#[cryptonamo(partition_key = "email")]
pub struct License {
    email: String,
    number: String,
    expires: String,
    #[allow(dead_code)]
    #[cryptonamo(skip)]
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
    fn test_cryptonamo_typename() {
        assert_eq!(License::type_name(), "license");
    }

    #[test]
    fn test_cryptonamo_instance() {
        let license = License::new("person@example.net", "1234", "2020-01-01");
        assert_eq!(license.partition_key(), "person@example.net");
        assert_eq!(
            License::protected_attributes(),
            vec!["email", "number", "expires"]
        );
        assert!(License::plaintext_attributes().is_empty());
    }
}
