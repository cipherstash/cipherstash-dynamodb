mod attrs;
mod b64_encode;
mod sealed;
mod sealer;
mod unsealed;
use crate::{
    traits::{PrimaryKeyError, PrimaryKeyParts, ReadConversionError, WriteConversionError},
    Identifiable, IndexType, PrimaryKey,
};
use cipherstash_client::{
    encryption::{EncryptionError, TypeParseError},
    zerokms,
};
use miette::Diagnostic;
use std::borrow::Cow;
use thiserror::Error;

// Re-exports
pub use b64_encode::*;
pub use sealed::{SealedTableEntry, UnsealSpec};
pub use sealer::{Sealer, UnsealedIndex};
pub use unsealed::Unsealed;

/// In order to stop indexes from exploding with indexes on large strings, cap the number of terms
/// generated per index. Since there is a fixed number of terms per index it is also possible to
/// delete all index terms for a particular record.
const MAX_TERMS_PER_INDEX: usize = 25;

#[derive(Debug, Error, Diagnostic)]
pub enum SealError {
    #[error("Error when creating primary key: {0}")]
    PrimaryKeyError(#[from] PrimaryKeyError),
    #[error("ReadConversionError: {0}")]
    ReadConversionError(#[from] ReadConversionError),
    #[error("WriteConversionError: {0}")]
    WriteConversionError(#[from] WriteConversionError),
    #[error("TypeParseError: {0}")]
    TypeParseError(#[from] TypeParseError),
    #[error("Missing attribute: {0}")]
    MissingAttribute(String),
    #[error("Invalid ciphertext value: {0}")]
    InvalidCiphertext(String),
    #[error("Assertion failed: {0}")]
    AssertionFailed(String),

    #[error(transparent)]
    CryptoError(#[from] zerokms::Error),

    /// Error resulting from Indexing in `cipherstash_client::encryption::compound_indexer`
    #[error(transparent)]
    IndexError(#[from] EncryptionError),
}

// TODO: Possibly remove this
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("EncryptionError: {0}")]
    EncryptionError(#[from] EncryptionError),
    #[error("ReadConversionError: {0}")]
    ReadConversionError(#[from] ReadConversionError),
    #[error("{0}")]
    Other(String),
}

pub fn format_term_key(
    sort_key: &str,
    index_name: &str,
    index_type: IndexType,
    counter: usize,
) -> String {
    format!("{sort_key}#{index_name}#{index_type}#{counter}")
}

/// Get all the term index keys for a particular sort key and index definitions
///
/// This is used to delete any index items that shouldn't exist during either an update or
pub(crate) fn all_index_keys<'a>(
    sort_key: &str,
    protected_indexes: impl AsRef<[(Cow<'a, str>, IndexType)]>,
) -> Vec<String> {
    protected_indexes
        .as_ref()
        .iter()
        .flat_map(|(index_name, index_type)| {
            (0..)
                .take(MAX_TERMS_PER_INDEX)
                .map(|i| format_term_key(sort_key, index_name, *index_type, i))
                .collect::<Vec<String>>()
        })
        .collect()
}

#[derive(Clone)]
pub struct PreparedPrimaryKey {
    pub primary_key_parts: PrimaryKeyParts,
    pub is_pk_encrypted: bool,
    pub is_sk_encrypted: bool,
}

impl PreparedPrimaryKey {
    pub fn new<R>(k: impl Into<R::PrimaryKey>) -> Self
    where
        R: Identifiable,
    {
        let primary_key_parts = k
            .into()
            .into_parts(&R::type_name(), R::sort_key_prefix().as_deref());

        Self::new_from_parts::<R>(primary_key_parts)
    }

    pub fn new_from_parts<R>(primary_key_parts: PrimaryKeyParts) -> Self
    where
        R: Identifiable,
    {
        Self {
            primary_key_parts,
            is_pk_encrypted: R::is_pk_encrypted(),
            is_sk_encrypted: R::is_sk_encrypted(),
        }
    }
}
