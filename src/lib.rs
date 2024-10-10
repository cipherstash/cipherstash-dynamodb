#![doc(
    html_favicon_url = "https://cipherstash.com/favicon.ico",
    html_logo_url = "https://raw.githubusercontent.com/cipherstash/meta/main/cipherstash-logo.svg"
)]
#![doc = include_str!("../README.md")]
pub mod crypto;
pub mod encrypted_table;
pub mod traits;
use encrypted_table::DynamoRecordPatch;
pub use encrypted_table::{EncryptedTable, QueryBuilder};
pub use traits::{
    Decryptable, Encryptable, Identifiable, IndexType, Pk, PkSk, PrimaryKey, Searchable,
    SingleIndex,
};

pub mod errors;
pub use errors::Error;

#[doc(hidden)]
pub use cipherstash_dynamodb_derive::{Decryptable, Encryptable, Identifiable, Searchable};

// Re-exports
pub use cipherstash_client::encryption;

pub type Key = [u8; 32];


pub struct Put<T> {
    record: T,
}

impl<T> Put<T> where T: Encryptable + Identifiable {
    pub fn new(record: T) -> Self {
        Self { record }
    }
}

pub struct Cipher {}

impl Cipher {
}

pub trait IntoPatch<Op> {
    fn seal(&self, op: Op) -> Result<DynamoRecordPatch, Error>;
}

impl<T> IntoPatch<Put<T>> for Cipher {
    fn seal(&self, op: Put<T>) -> Result<DynamoRecordPatch, Error> {
        unimplemented!()
    }
}
