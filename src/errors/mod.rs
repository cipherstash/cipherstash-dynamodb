use aws_sdk_dynamodb::{error::SdkError, operation};
use cipherstash_client::zerokms;
use miette::Diagnostic;
use thiserror::Error;

use crate::traits::PrimaryKeyError;
pub use crate::{
    crypto::{CryptoError, SealError},
    traits::{ReadConversionError, WriteConversionError},
};

pub use cipherstash_client::{config::errors::ConfigError, encryption::EncryptionError};

pub use aws_sdk_dynamodb::error::BuildError;

/// Error returned by `EncryptedTable::put` when indexing, encrypting and inserting records into DynamoDB
#[derive(Error, Debug, Diagnostic)]
pub enum PutError {
    #[error("PrimaryKeyError: {0}")]
    PrimaryKeyError(#[from] PrimaryKeyError),
    // TODO: Get rid of this, too?
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

    #[error(transparent)]
    DynamoError(#[from] SdkError<operation::transact_write_items::TransactWriteItemsError>),

    #[error("ZeroKMS Error: {0}")]
    ZeroKMS(#[from] zerokms::Error),
}

/// Error returned by `EncryptedTable::get` when retrieving and decrypting records from DynamoDB
#[derive(Error, Debug, Diagnostic)]
pub enum GetError {
    #[error(transparent)]
    PrimaryKeyError(#[from] PrimaryKeyError),
    #[error(transparent)]
    DecryptError(#[from] DecryptError),
    #[error(transparent)]
    Encryption(#[from] EncryptionError),
    #[error("AwsError: {0}")]
    Aws(String),
}

/// Error returned by `EncryptedTable::delete` when indexing and deleting records in DynamoDB
#[derive(Error, Debug, Diagnostic)]
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
#[derive(Error, Debug, Diagnostic)]
pub enum DecryptError {
    #[error(transparent)]
    ReadConversionError(#[from] ReadConversionError),
    #[error(transparent)]
    SealError(#[from] SealError),
}

/// Error returned by `EncryptedTable::query` when indexing, retrieving and decrypting records from DynamoDB
#[derive(Error, Debug, Diagnostic)]
pub enum EncryptError {
    #[error(transparent)]
    WriteConversionError(#[from] ReadConversionError),
    #[error(transparent)]
    SealError(#[from] SealError),
}

/// Error returned by [`crate::EncryptedTable::query`] when indexing, retrieving and decrypting records from DynamoDB
#[derive(Error, Debug, Diagnostic)]
pub enum QueryError {
    #[error("PrimaryKeyError: {0}")]
    PrimaryKeyError(#[from] PrimaryKeyError),
    #[error("InvaldQuery: {0}")]
    InvalidQuery(String),
    #[error("{0}")]
    Other(String),

    #[error(transparent)]
    SealError(#[from] SealError),

    // TODO: Consider removing this
    #[error(transparent)]
    DecryptError(#[from] DecryptError),

    #[error(transparent)]
    DynamoError(#[from] SdkError<operation::query::QueryError>),
}

pub trait DynamoError: std::error::Error + Sized {}

/// Error returned by `EncryptedTable::init` when connecting to CipherStash services
#[derive(Error, Debug, Diagnostic)]
pub enum InitError {
    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error(transparent)]
    ZeroKMS(#[from] zerokms::Error),
}

/// The [`enum@Error`] type abstracts all errors returned by `cipherstash-dynamodb` for easy use with the `?` operator.
#[derive(Error, Debug, Diagnostic)]
pub enum Error {
    #[error("InitError: {0}")]
    InitError(#[from] InitError),
    #[error("PutError: {0}")]
    PutError(#[from] PutError),
    #[error("GetError: {0}")]
    GetError(#[from] GetError),
    #[error("DeleteError: {0}")]
    DeleteError(#[from] DeleteError),
    #[error(transparent)]
    QueryError(#[from] QueryError),
}
