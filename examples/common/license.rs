use cryptonamo::Cryptonamo;

#[derive(Debug, Cryptonamo)]
#[cryptonamo(partition_key = "email")]
pub struct License {
    #[cryptonamo(skip)]
    email: String,
    number: String,
    expires: String,
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
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use super::License;
    use cryptonamo::traits::*;
    
    #[test]
    fn test_cryptonamo_typename() {
        assert_eq!(License::type_name(), "license");
    }

    #[test]
    fn test_cryptonamo_instance() {
        let license = License::new("person@example.net", "1234", "2020-01-01");
        assert_eq!(license.partition_key(), "person@example.net");
        assert_eq!(
            license.protected_attributes(),
            HashMap::from([
                ("number", "1234".into()),
                ("expires", "2020-01-01".into()),
            ])
        );
        assert!(license.plaintext_attributes().is_empty());
    }
}
