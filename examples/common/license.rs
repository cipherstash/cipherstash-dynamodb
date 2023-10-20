use cryptonamo::{DecryptedRecord, DynamoTarget, EncryptedRecord, Plaintext};
use std::collections::HashMap;

#[derive(Debug)]
pub struct License {
    email: Option<String>,
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
            email: Some(email.into()),
            number: number.into(),
            expires: expires.into(),
        }
    }
}

impl EncryptedRecord for License {
    fn partition_key(&self) -> String {
        // NOTE: Partition key for subtypes is required on insert
        self.email.as_ref().unwrap().to_string()
    }

    fn attributes(&self) -> HashMap<String, Plaintext> {
        HashMap::from([
            (
                "number".to_string(),
                Plaintext::Utf8Str(Some(self.number.to_string())),
            ),
            (
                "expires".to_string(),
                Plaintext::Utf8Str(Some(self.expires.to_string())),
            ),
        ])
    }
}

impl DynamoTarget for License {
    fn type_name() -> &'static str {
        "license"
    }
}

impl DecryptedRecord for License {
    fn from_attributes(attributes: HashMap<String, Plaintext>) -> Self {
        Self {
            number: attributes.get("number").unwrap().try_into().unwrap(),
            expires: attributes.get("expires").unwrap().try_into().unwrap(),
            email: None,
        }
    }
}
