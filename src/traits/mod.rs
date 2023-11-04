use crate::crypto::{Unsealed, Sealer, SealError};
pub use crate::{
    encrypted_table::TableAttribute,
};
pub use cipherstash_client::encryption::{
    compound_indexer::{
        ComposableIndex, ComposablePlaintext, CompoundIndex, ExactIndex, PrefixIndex,
    },
    Plaintext,
};
use std::fmt::Debug;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReadConversionError {
    #[error("Missing attribute: {0}")]
    NoSuchAttribute(String),
    #[error("Failed to convert attribute: {0} from Plaintext")]
    ConversionFailed(String),
}

#[derive(Debug, Error)]
pub enum WriteConversionError {
    #[error("Failed to convert attribute: '{0}' to Plaintext")]
    ConversionFailed(String),
}

pub trait Cryptonamo: Debug + Sized {
    // TODO: Add a function indicating that the root should be stored
    fn type_name() -> &'static str;
    fn partition_key(&self) -> String;
}

// These are analogous to serde (rename to Encrypt and Decrypt)
pub trait EncryptedRecord: Cryptonamo {
    fn protected_attributes() -> Vec<&'static str>;

    fn plaintext_attributes() -> Vec<&'static str> {
        vec![]
    }

    fn into_sealer(self) -> Result<Sealer<Self>, SealError>;
}

pub trait SearchableRecord: EncryptedRecord {
    // FIXME: This would be cleaner with a DSL
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

/*
We need to identify which fields from TableAttributes are encrypted and which are plaintext.
Decrypt the ciphertexts and convert them all into the final record.
Conversion would take the that were decrypted and a subset of the TableAttributes.
*/

pub trait DecryptedRecord: EncryptedRecord {
    /// Convert an `Unsealed` into a `Self`.
    fn from_unsealed(unsealed: Unsealed) -> Result<Self, SealError>;

    /// Defines which attributes are decryptable for this type.
    /// Must be equal to or a subset of protected_attributes().
    /// By default, this is the same as protected_attributes().
    fn decryptable_attributes() -> Vec<&'static str> {
        Self::protected_attributes()
    }
}
