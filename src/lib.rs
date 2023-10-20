use std::{collections::HashMap, fmt::Debug};

mod crypto;
pub mod encrypted_table;
mod table_entry;

pub type Key = [u8; 32];

// Re-exports
pub use cipherstash_client::encryption::Plaintext;

pub enum CompoundAttribute {
    Exact(String, String),
    BeginsWith(String, String),
}

// These are analogous to serde (rename to Encrypt and Decrypt)
pub trait EncryptedRecord: DynamoTarget {
    fn partition_key(&self) -> String;
    fn attributes(&self) -> HashMap<String, Plaintext>;

    fn composite_attributes(&self) -> Vec<CompoundAttribute> {
        Vec::with_capacity(0)
    }
}

pub trait DecryptedRecord: DynamoTarget {
    fn from_attributes(attributes: HashMap<String, Plaintext>) -> Self;
}

pub trait DynamoTarget: Debug {
    fn type_name() -> &'static str;
}
