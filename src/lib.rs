use std::{collections::HashMap, fmt::Debug};
mod crypto;
mod encrypted_table;
mod table_entry;
pub use encrypted_table::{EncryptedTable, QueryBuilder};

// Re-exports
use cipherstash_client::encryption::compound_indexer::{ComposableIndex, ComposablePlaintext};
pub use cipherstash_client::encryption::Plaintext;

pub type Key = [u8; 32];

// These are analogous to serde (rename to Encrypt and Decrypt)
pub trait EncryptedRecord: DynamoTarget + Sized {
    fn partition_key(&self) -> String;
    fn protected_attributes(&self) -> HashMap<String, Plaintext>;
}

pub trait SearchableRecord: EncryptedRecord {
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
