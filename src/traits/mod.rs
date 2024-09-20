use crate::crypto::{SealError, Unsealed};
pub use crate::encrypted_table::{TableAttribute, TryFromTableAttr};
use cipherstash_client::encryption::EncryptionError;
pub use cipherstash_client::{
    credentials::{service_credentials::ServiceToken, Credentials},
    encryption::{
        compound_indexer::{
            ComposableIndex, ComposablePlaintext, CompoundIndex, ExactIndex, PrefixIndex,
        },
        Encryption, Plaintext, PlaintextNullVariant, TryFromPlaintext,
    },
};

mod primary_key;
pub use primary_key::*;

use std::{
    borrow::Cow,
    fmt::{Debug, Display},
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SingleIndex {
    Exact,
    Prefix,
}

impl Display for SingleIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exact => f.write_str("exact"),
            Self::Prefix => f.write_str("prefix"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IndexType {
    Single(SingleIndex),
    Compound2((SingleIndex, SingleIndex)),
}

impl Display for IndexType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single(index) => Display::fmt(index, f),
            Self::Compound2((index_a, index_b)) => {
                Display::fmt(index_a, f)?;
                f.write_str(":")?;
                Display::fmt(index_b, f)?;
                Ok(())
            }
        }
    }
}

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

#[derive(Error, Debug)]
pub enum PrimaryKeyError {
    #[error("EncryptionError: {0}")]
    EncryptionError(#[from] EncryptionError),
    #[error("PrimaryKeyError: {0}")]
    Unknown(String),
}

pub trait Identifiable {
    type PrimaryKey: PrimaryKey;

    fn get_primary_key(&self) -> Self::PrimaryKey;

    fn is_sk_encrypted() -> bool {
        false
    }

    fn is_pk_encrypted() -> bool {
        false
    }

    fn type_name() -> Cow<'static, str>;
    fn sort_key_prefix() -> Option<Cow<'static, str>>;
}

pub trait Encryptable: Debug + Sized + Identifiable {
    /// Defines what attributes are protected and should be encrypted for this type.
    ///
    /// Must be equal to or a superset of protected_attributes on the [`Decryptable`] type.
    fn protected_attributes() -> Cow<'static, [Cow<'static, str>]>;

    /// Defines what attributes are plaintext for this type.
    ///
    /// Must be equal to or a superset of plaintext_attributes on the [`Decryptable`] type.
    fn plaintext_attributes() -> Cow<'static, [Cow<'static, str>]>;

    fn into_unsealed(self) -> Unsealed;
}

pub trait Searchable: Encryptable {
    fn attribute_for_index(
        &self,
        _index_name: &str,
        _index_type: IndexType,
    ) -> Option<ComposablePlaintext> {
        None
    }

    fn protected_indexes() -> Cow<'static, [(Cow<'static, str>, IndexType)]> {
        Cow::Borrowed(&[])
    }

    fn index_by_name(
        _index_name: &str,
        _index_type: IndexType,
    ) -> Option<Box<dyn ComposableIndex + Send>> {
        None
    }
}

pub trait Decryptable: Sized {
    /// Convert an `Unsealed` into a `Self`.
    fn from_unsealed(unsealed: Unsealed) -> Result<Self, SealError>;

    /// Defines what attributes are protected and decryptable for this type.
    ///
    /// Must be equal to or a subset of protected_attributes on the [`Encryptable`] type.
    fn protected_attributes() -> Cow<'static, [Cow<'static, str>]>;

    /// Defines what attributes are plaintext for this type.
    ///
    /// Must be equal to or a subset of protected_attributes on the [`Encryptable`] type.
    fn plaintext_attributes() -> Cow<'static, [Cow<'static, str>]>;
}
