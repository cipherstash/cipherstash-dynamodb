use cryptonamo::{
    traits::DecryptedRecord,
    Cryptonamo, Plaintext,
};
use std::collections::HashMap;

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

impl DecryptedRecord for License {
    fn from_attributes(attributes: HashMap<String, Plaintext>) -> Self {
        Self {
            number: attributes.get("number").unwrap().try_into().unwrap(),
            expires: attributes.get("expires").unwrap().try_into().unwrap(),
            email: attributes.get("email").unwrap().try_into().unwrap(),
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
