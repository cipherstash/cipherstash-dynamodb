use thiserror::Error;

use crate::traits::PrimaryKeyError;
pub use crate::{
    crypto::{CryptoError, SealError},
    traits::{ReadConversionError, WriteConversionError},
};

pub use cipherstash_client::{
    config::errors::ConfigError, encryption::EncryptionError, zero_kms::errors::LoadConfigError,
};

pub use aws_sdk_dynamodb::error::BuildError;

/// Error returned by `EncryptedTable::put` when indexing, encrypting and inserting records into DynamoDB
#[derive(Error, Debug)]
pub enum PutError {
    #[error("PrimaryKeyError: {0}")]
    PrimaryKeyError(#[from] PrimaryKeyError),
    #[error("AwsError: {0}")]
    Aws(String),
    #[error("AwsBuildError: {0}")]
    AwsBuildError(#[from] BuildError),
    #[error("Write Conversion Error: {0}")]
    WriteConversion(#[from] WriteConversionError),
    #[error("SealError: {0}")]
    Seal(#[from] SealError),
    #[error("CryptoError: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Encryption Error: {0}")]
    Encryption(#[from] EncryptionError),
}

/// Error returned by `EncryptedTable::get` when retrieving and decrypting records from DynamoDB
#[derive(Error, Debug)]
pub enum GetError {
    #[error("PrimaryKeyError: {0}")]
    PrimaryKeyError(#[from] PrimaryKeyError),
    #[error("Decrypt Error: {0}")]
    DecryptError(#[from] DecryptError),
    #[error("Encryption Error: {0}")]
    Encryption(#[from] EncryptionError),
    #[error("AwsError: {0}")]
    Aws(String),
}

/// Error returned by `EncryptedTable::delete` when indexing and deleting records in DynamoDB
#[derive(Error, Debug)]
pub enum DeleteError {
    #[error("PrimaryKeyError: {0}")]
    PrimaryKeyError(#[from] PrimaryKeyError),
    #[error("Encryption Error: {0}")]
    Encryption(#[from] EncryptionError),
    #[error("AwsBuildError: {0}")]
    AwsBuildError(#[from] BuildError),
    #[error("AwsError: {0}")]
    Aws(String),
}

/// Error returned by `EncryptedTable::query` when indexing, retrieving and decrypting records from DynamoDB
#[derive(Error, Debug)]
pub enum DecryptError {
    #[error("ReadConversionError: {0}")]
    ReadConversionError(#[from] ReadConversionError),
    #[error("SealError: {0}")]
    SealError(#[from] SealError),
}

/// Error returned by [`EncryptedTable::query`] when indexing, retrieving and decrypting records from DynamoDB
#[derive(Error, Debug)]
pub enum QueryError {
    #[error("PrimaryKeyError: {0}")]
    PrimaryKeyError(#[from] PrimaryKeyError),
    #[error("InvaldQuery: {0}")]
    InvalidQuery(String),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("EncryptionError: {0}")]
    EncryptionError(#[from] EncryptionError),
    #[error("Decrypt Error: {0}")]
    DecryptError(#[from] DecryptError),
    #[error("AwsError: {0}")]
    AwsError(String),
    #[error("{0}")]
    Other(String),
}

/// Error returned by `EncryptedTable::init` when connecting to CipherStash services
#[derive(Error, Debug)]
pub enum InitError {
    #[error("ConfigError: {0}")]
    Config(#[from] ConfigError),
    #[error("LoadConfigError: {0}")]
    LoadConfig(#[from] LoadConfigError),
}

/// The [`enum@Error`] type abstracts all errors returned by `cipherstash-dynamodb` for easy use with the `?` operator.
#[derive(Error, Debug)]
pub enum Error {
    #[error("InitError: {0}")]
    InitError(#[from] InitError),
    #[error("PutError: {0}")]
    PutError(#[from] PutError),
    #[error("GetError: {0}")]
    GetError(#[from] GetError),
    #[error("DeleteError: {0}")]
    DeleteError(#[from] DeleteError),
    #[error("QueryError: {0}")]
    QueryError(#[from] QueryError),
}
