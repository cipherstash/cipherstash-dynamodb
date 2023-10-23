use std::{collections::HashMap, fmt::Debug};

mod crypto;
pub mod encrypted_table;
mod table_entry;

pub type Key = [u8; 32];

// Re-exports
use cipherstash_client::encryption::compound_indexer::{
    ComposableIndex, ComposablePlaintext, ConsArg2, ConsArg3,
};
pub use cipherstash_client::encryption::Plaintext;

#[derive(Debug)]
pub enum CompoundAttributeOrig {
    Exact(String, String),
    BeginsWith(String, String),
}

// These are analogous to serde (rename to Encrypt and Decrypt)
pub trait EncryptedRecord: DynamoTarget {
    fn partition_key(&self) -> String;
    fn protected_attributes(&self) -> HashMap<String, Plaintext>;

    #[allow(unused_variables)]
    fn attribute_for_index(&self, index_name: &str) -> Option<ComposablePlaintext> {
        None
    }

    fn protected_indexes() -> Vec<&'static str> {
        vec![]
    }

    #[allow(unused_variables)]
    fn index_by_name(name: &str) -> Option<Box<dyn ComposableIndex>> {
        None
    }
}

pub trait DecryptedRecord: DynamoTarget {
    fn from_attributes(attributes: HashMap<String, Plaintext>) -> Self;
}

pub trait DynamoTarget: Debug {
    fn type_name() -> &'static str;
}
