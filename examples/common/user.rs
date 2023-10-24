use cipherstash_client::encryption::compound_indexer::{
    ComposableIndex, ComposablePlaintext, CompoundIndex, ExactIndex, PrefixIndex,
};
use cryptonamo::{Plaintext, Cryptonamo, EncryptedRecord, traits::{DecryptedRecord, SearchableRecord}};
use std::collections::HashMap;

#[derive(Debug, Cryptonamo, EncryptedRecord)]
#[cryptonamo(partition_key = "email")]
#[cryptonamo(sort_key_prefix = "user")]
pub struct User {
    pub email: String,
    pub name: String,

    #[cryptonamo(plaintext)]
    pub count: i32,
}

impl User {
    #[allow(dead_code)]
    pub fn new(email: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            name: name.into(),
            count: 100,
        }
    }
}

impl SearchableRecord for User {
    fn protected_indexes() -> Vec<&'static str> {
        vec!["name", "email#name"]
    }

    fn index_by_name(name: &str) -> Option<Box<dyn ComposableIndex>> {
        match name {
            "name" => Some(Box::new(PrefixIndex::new("name", vec![], 3, 10))),
            "email#name" => Some(Box::new(
                CompoundIndex::new(ExactIndex::new("email", vec![])).and(PrefixIndex::new(
                    "name",
                    vec![],
                    3,
                    10,
                )),
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
}

impl DecryptedRecord for User {
    fn from_attributes(attributes: HashMap<String, Plaintext>) -> Self {
        Self {
            email: attributes.get("email").unwrap().try_into().unwrap(),
            name: attributes.get("name").unwrap().try_into().unwrap(),
            count: 100,
        }
    }
}
