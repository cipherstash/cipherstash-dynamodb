mod crypto;
mod encrypted_table;
pub mod traits;
pub use encrypted_table::{EncryptedTable, QueryBuilder};

// Re-exports
pub use cipherstash_client::encryption::compound_indexer::{ComposableIndex, ComposablePlaintext};
pub use cipherstash_client::encryption::Plaintext;

    let expanded = quote! {
        use cryptonamo::target::DynamoTarget;

pub use cryptonamo_derive::Cryptonamo;
