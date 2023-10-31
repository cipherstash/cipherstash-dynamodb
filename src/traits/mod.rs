use crate::{
    encrypted_table::Unsealed,
    ComposableIndex, ComposablePlaintext, Plaintext,
};
use std::{collections::HashMap, fmt::Debug};
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

    fn into_unsealed(self) -> Result<Unsealed<Self>, WriteConversionError>;
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
    /// Returns the ciphertext values to be decrypted
    fn ciphertexts(&self) -> HashMap<&'static str, String>;

    fn from_attributes(attributes: HashMap<String, Plaintext>)
        -> Result<Self, ReadConversionError>;

    fn from_unsealed(unsealed: Unsealed<Self>) -> Result<Self, ReadConversionError>;
}
