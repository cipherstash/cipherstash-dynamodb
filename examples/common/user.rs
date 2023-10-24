use cipherstash_client::encryption::compound_indexer::{
    ComposableIndex, ComposablePlaintext, CompoundIndex, ExactIndex, PrefixIndex,
};
use cryptonamo::{DecryptedRecord, DynamoTarget, EncryptedRecord, Plaintext};
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

    fn protected_indexes() -> Vec<&'static str> {
        vec!["name", "email#name"]
    }

    fn index_by_name(name: &str) -> Option<Box<dyn ComposableIndex>> {
        match name {
            "name" => Some(Box::new(ExactIndex::new("name", vec![]))),
            "email#name" => Some(Box::new(
                CompoundIndex::new(ExactIndex::new("email", vec![])).and(PrefixIndex::new("name", vec![], 3, 10)),
            )),
            _ => None,
        }
    }

    fn attribute_for_index(&self, index_name: &str) -> Option<ComposablePlaintext> {
        match index_name {
            "name" => Some(ComposablePlaintext::from(self.name.to_string())),
            "email#name" => (self.email.to_string(), self.name.to_string())
                .try_into()
                .ok(),
            _ => None,
        }
    }

    fn protected_attributes(&self) -> HashMap<String, Plaintext> {
        HashMap::from([
            ("name".to_string(), self.name.to_string().into()),
            ("email".to_string(), self.email.to_string().into()),
        ])
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
