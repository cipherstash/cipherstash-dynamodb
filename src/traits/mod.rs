use crate::crypto::{SealError, Sealer, Unsealed};
pub use crate::encrypted_table::TableAttribute;
pub use cipherstash_client::encryption::{
    compound_indexer::{
        ComposableIndex, ComposablePlaintext, CompoundIndex, ExactIndex, PrefixIndex,
    },
    Plaintext, PlaintextNullVariant, ToPlaintext, TryFromPlaintext,
};

mod primary_key;
pub use primary_key::*;

use std::fmt::Debug;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReadConversionError {
    #[error("Missing attribute: {0}")]
    NoSuchAttribute(String),
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    #[error("Failed to convert attribute: {0} from Plaintext")]
    ConversionFailed(String),
}

#[derive(Debug, Error)]
pub enum WriteConversionError {
    #[error("Failed to convert attribute: '{0}' to Plaintext")]
    ConversionFailed(String),
}

pub trait Encryptable: Debug + Sized {
    type PrimaryKey: PrimaryKey;

    // TODO: Add a function indicating that the root should be stored
    fn type_name() -> &'static str;

    fn sort_key_prefix() -> Option<&'static str>;

    fn is_partition_key_encrypted() -> bool;

    fn is_sort_key_encrypted() -> bool;

    fn sort_key(&self) -> String {
        Self::type_name().into()
    }

    fn partition_key(&self) -> String;

    fn protected_attributes() -> Vec<&'static str>;

    fn plaintext_attributes() -> Vec<&'static str> {
        vec![]
    }

    fn into_sealer(self) -> Result<Sealer<Self>, SealError>;
}

pub trait Searchable: Encryptable {
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

pub trait Decryptable: Encryptable {
    /// Convert an `Unsealed` into a `Self`.

    fn from_unsealed(unsealed: Unsealed) -> Result<Self, SealError>;

    /// Defines which attributes are decryptable for this type.
    /// Must be equal to or a subset of protected_attributes().
    /// By default, this is the same as protected_attributes().
    fn decryptable_attributes() -> Vec<&'static str> {
        Self::protected_attributes()
    }
}
