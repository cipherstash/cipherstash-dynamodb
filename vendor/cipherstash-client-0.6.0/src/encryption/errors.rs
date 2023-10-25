use super::{compound_indexer::AccumulatorError, plaintext::Plaintext};
use crate::vitur::errors::{DecryptError, EncryptError};
use cipherstash_core::string::OrderiseStringError;
use hex::FromHexError;
use hmac::digest::InvalidLength;
use miette::Diagnostic;
use ore_rs::OreError;
use static_assertions::assert_impl_all;
use std::fmt::{Debug, Display};
use thiserror::Error;

#[derive(Debug, Error, Diagnostic)]
pub enum EncryptionError {
    #[error(transparent)]
    EncodingError(#[from] FromHexError),
    #[error(transparent)]
    SerDeError(#[from] serde_cbor::Error),
    #[diagnostic(transparent)]
    #[error(transparent)]
    EncryptError(#[from] EncryptError),
    #[diagnostic(transparent)]
    #[error(transparent)]
    DecryptError(#[from] DecryptError),
    #[error(transparent)]
    TypeParseError(#[from] TypeParseError),
    #[error("Unable to index value: `{0}`")]
    IndexingError(String),
    #[error(transparent)]
    InvalidUniqueKey(#[from] InvalidLength),
    #[error("ORE Error: {0}")]
    OreError(#[from] OreError),
    #[error("Orderise string error: {0}")]
    OrderiseStringError(#[from] OrderiseStringError),
    #[error("Accumulator error: {0}")]
    AccumulatorError(#[from] AccumulatorError),
    #[error("Too many arguments provided")]
    TooManyArguments,
    #[error("Too few arguments provided")]
    TooFewArguments,
    // FIXME: Probably too broad an error
    #[error("Unable to convert value to target type")]
    ConversionError,
}

// Make sure that encryption errors can be sent between threads so encryptions can be run on
// different threads
assert_impl_all!(EncryptionError: Send, Sync);

#[derive(Debug, Error)]
pub struct TypeParseError(pub String);

impl TypeParseError {
    pub(crate) fn make(value: &[u8], variant: u8) -> Self {
        let target = Plaintext::variant_name(variant);
        Self(format!(
            "Unable to parse value, {value:?} into type {target:?}"
        ))
    }
}

impl Display for TypeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
