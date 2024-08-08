mod b64_encode;
mod sealed;
mod sealer;
mod unsealed;

use std::borrow::Cow;

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
};
use thiserror::Error;

pub use b64_encode::*;
pub use sealed::{SealedTableEntry, UnsealSpec};
pub use sealer::Sealer;
pub use unsealed::Unsealed;

const MAX_TERMS_PER_INDEX: usize = 25;

#[derive(Debug, Error)]
pub enum SealError {
    #[error("Error when creating primary key: {0}")]
    PrimaryKeyError(#[from] PrimaryKeyError),
    #[error("Failed to encrypt partition key")]
    CryptoError(#[from] EncryptionError),
    #[error("Failed to convert attribute: {0} from internal representation")]
    ReadConversionError(#[from] ReadConversionError),
    #[error("Failed to convert attribute: {0} to internal representation")]
    WriteConversionError(#[from] WriteConversionError),
    // TODO: Does TypeParseError correctly redact the plaintext value?
    #[error("Failed to parse type for encryption: {0}")]
    TypeParseError(#[from] TypeParseError),
    #[error("Missing attribute: {0}")]
    MissingAttribute(String),
    #[error("Invalid ciphertext value: {0}")]
    InvalidCiphertext(String),
    #[error("Assertion failed: {0}")]
    AssertionFailed(String),
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

pub fn hmac<C>(
    value: &str,
    salt: Option<&str>,
    cipher: &Encryption<C>,
) -> Result<Vec<u8>, EncryptionError>
where
    C: Credentials<Token = ServiceToken>,
{
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

        Self {
            primary_key_parts,
            is_pk_encrypted: R::is_pk_encrypted(),
            is_sk_encrypted: R::is_sk_encrypted(),
        }
    }
}
