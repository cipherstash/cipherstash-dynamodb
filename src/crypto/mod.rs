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
    credentials::{service_credentials::ServiceToken, Credentials},
    encryption::{
        compound_indexer::{CompoundIndex, ExactIndex},
        Encryption, EncryptionError, Plaintext, TypeParseError,
    },
    zerokms::Error as ZeroKmsError,
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

    // Note that we don't expose the specific error type here
    // so as to avoid leaking any information
    #[error(transparent)]
    EncryptionError(#[from] EncryptionError),

    #[error(transparent)]
    ZeroKmsError(#[from] ZeroKmsError),
}

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

/// Use a CipherStash [`ExactIndex`] to take the HMAC of a string with a provided salt
///
/// This value is used for term index keys and "encrypted" partition / sort keys
pub fn hmac(
    value: &str,
    salt: Option<&str>,
    cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
) -> Result<Vec<u8>, EncryptionError> {
    let plaintext = Plaintext::Utf8Str(Some(value.to_string()));
    let index = CompoundIndex::new(ExactIndex::new(vec![]));

    cipher
        .compound_index(
            &index,
            plaintext,
            // passing None here results in no terms so pass an empty string
            Some(salt.unwrap_or("")),
            32,
        )?
        .as_binary()
        .ok_or(EncryptionError::IndexingError(
            "Invalid term type".to_string(),
        ))
}

// Contains all the necessary information to encrypt the primary key pair
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
