
mod crypto;
pub mod traits;
mod encrypted_table;
pub use encrypted_table::{EncryptedTable, QueryBuilder};

// Re-exports
use cipherstash_client::encryption::compound_indexer::{ComposableIndex, ComposablePlaintext};
pub use cipherstash_client::encryption::Plaintext;

pub type Key = [u8; 32];

pub use cryptonamo_derive::{Cryptonamo, EncryptedRecord};
