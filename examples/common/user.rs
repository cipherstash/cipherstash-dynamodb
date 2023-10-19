use cryptonamo::{CompositeAttribute, DecryptedRecord, DynamoTarget, EncryptedRecord, Plaintext};
use std::collections::HashMap;

#[derive(Debug)]
pub struct User {
    pub email: String,
    pub name: String,
}

impl User {
    #[allow(dead_code)]
    pub fn new(email: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            name: name.into(),
        }
    }
}

impl EncryptedRecord for User {
    fn partition_key(&self) -> String {
        self.email.to_string()
    }

    fn attributes(&self) -> HashMap<String, Plaintext> {
        HashMap::from([
            ("name".to_string(), Plaintext::from(self.name.to_string())),
            ("email".to_string(), Plaintext::from(self.email.to_string())),
        ])
    }

    fn composite_attributes(&self) -> Vec<CompositeAttribute> {
        vec![CompositeAttribute::Match("name".into(), "email".into())]
    }
}

impl DynamoTarget for User {
    fn type_name() -> &'static str {
        "user"
    }
}

impl DecryptedRecord for User {
    fn from_attributes(attributes: HashMap<String, Plaintext>) -> Self {
        Self {
            email: attributes.get("email").unwrap().try_into().unwrap(),
            name: attributes.get("name").unwrap().try_into().unwrap(),
        }
    }
}
