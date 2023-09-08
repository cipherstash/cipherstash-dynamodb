use cryptonamo::{DecryptedRecord, DynamoTarget, Plaintext};
use std::collections::HashMap;

#[derive(Debug)]
pub struct UserResultByName {
    pub name: String,
}

impl DynamoTarget for UserResultByName {
    fn type_name() -> &'static str {
        "user"
    }
}

impl DecryptedRecord for UserResultByName {
    fn from_attributes(attributes: HashMap<String, Plaintext>) -> Self {
        // TODO: Don't unwrap, make try_from_attributes and return a Result
        Self {
            name: attributes.get("name").unwrap().try_into().unwrap(),
        }
    }
}
