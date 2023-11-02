use crate::{
    traits::{Cryptonamo, ReadConversionError, SearchableRecord},
};
use cipherstash_client::{
    credentials::{vitur_credentials::ViturToken, Credentials},
    encryption::{
        Encryption, EncryptionError, Plaintext,
    },
    schema::column::Index,
};
use thiserror::Error;

const MAX_TERMS_PER_INDEX: usize = 25;

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
) -> Result<String, CryptoError>
where
    C: Credentials<Token = ViturToken>,
{
    let plaintext = Plaintext::Utf8Str(Some(value.to_string()));
    let index_type = Index::new_unique().index_type;

    cipher
        .index(&plaintext, &index_type)?
        .as_binary()
        .map(hex::encode)
        .ok_or_else(|| CryptoError::Other("Encrypting partition key returned invalid value".into()))
}
