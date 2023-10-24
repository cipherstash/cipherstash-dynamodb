use cryptonamo::{Cryptonamo, Plaintext, traits::{DecryptedRecord, EncryptedRecord, SearchableRecord}};
use std::collections::HashMap;

#[derive(Debug, Cryptonamo)]
#[cryptonamo(partition_key = "email")]
pub struct License {
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

impl EncryptedRecord for License {
    fn protected_attributes(&self) -> HashMap<&'static str, Plaintext> {
        HashMap::from([
            (
                "number",
                Plaintext::Utf8Str(Some(self.number.to_string())),
            ),
            (
                "expires",
                Plaintext::Utf8Str(Some(self.expires.to_string())),
            ),
        ])
    }
}

impl SearchableRecord for License {}

impl DecryptedRecord for License {
    fn from_attributes(attributes: HashMap<String, Plaintext>) -> Self {
        Self {
            number: attributes.get("number").unwrap().try_into().unwrap(),
            expires: attributes.get("expires").unwrap().try_into().unwrap(),
            email: attributes.get("email").unwrap().try_into().unwrap(),
        }
    }
}
