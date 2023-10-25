use cryptonamo::{traits::DecryptedRecord, Cryptonamo, Plaintext};
use std::collections::HashMap;

#[derive(Debug, Cryptonamo)]
#[cryptonamo(partition_key = "name")]
pub struct UserResultByName {
    pub name: String,
}

impl DecryptedRecord for UserResultByName {
    fn from_attributes(attributes: HashMap<String, Plaintext>) -> Self {
        // TODO: Don't unwrap, make try_from_attributes and return a Result
        Self {
            name: attributes.get("name").unwrap().try_into().unwrap(),
        }
    }
}
