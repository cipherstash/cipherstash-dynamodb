mod sealed;
mod sealer;
mod unsealed;

use crate::traits::{Cryptonamo, ReadConversionError, SearchableRecord, WriteConversionError};
use cipherstash_client::{
    credentials::{vitur_credentials::ViturToken, Credentials},
    encryption::{Encryption, EncryptionError, Plaintext, TypeParseError},
    schema::column::Index,
};
use thiserror::Error;

pub use sealer::Sealer;
pub use sealed::Sealed;
pub use unsealed::Unsealed;

const MAX_TERMS_PER_INDEX: usize = 25;


// TODO: Should we just call this CryptoError?
#[derive(Debug, Error)]
pub enum SealError {
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

pub(crate) fn all_index_keys<E: SearchableRecord + Cryptonamo>() -> Vec<String> {
    E::protected_indexes()
        .iter()
        .flat_map(|index_name| {
            (0..)
                .take(MAX_TERMS_PER_INDEX)
                .map(|i| format!("{}#{}#{}", E::type_name(), index_name, i))
                .collect::<Vec<String>>()
        })
        .collect()
}

pub(crate) fn encrypt_partition_key<C>(
    value: &str,
    cipher: &Encryption<C>,
) -> Result<String, EncryptionError>
where
    C: Credentials<Token = ViturToken>,
{
    let plaintext = Plaintext::Utf8Str(Some(value.to_string()));
    let index_type = Index::new_unique().index_type;

    cipher
        .index(&plaintext, &index_type)?
        .as_binary()
        .map(hex::encode)
        .ok_or(EncryptionError::IndexingError("Invalid term type".to_string()))
}
