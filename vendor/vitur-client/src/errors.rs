use miette::Diagnostic;
use recipher::errors::RecipherError;
use static_assertions::assert_impl_all;
use thiserror::Error;
use vitur_protocol::ViturRequestError;

#[derive(Diagnostic, Error, Debug)]
pub enum CreateDatasetError {
    #[error("Failed to send request: {0}")]
    RequestFailed(#[from] ViturRequestError),
}

#[derive(Diagnostic, Error, Debug)]
pub enum ListDatasetError {
    #[error("Failed to send request: {0}")]
    RequestFailed(#[from] ViturRequestError),
}

#[derive(Diagnostic, Error, Debug)]
pub enum EnableDatasetError {
    #[error("Failed to send request: {0}")]
    RequestFailed(#[from] ViturRequestError),
}

#[derive(Diagnostic, Error, Debug)]
pub enum DisableDatasetError {
    #[error("Failed to send request: {0}")]
    RequestFailed(#[from] ViturRequestError),
}

#[derive(Diagnostic, Error, Debug)]
pub enum ModifyDatasetError {
    #[error("Failed to send request: {0}")]
    RequestFailed(#[from] ViturRequestError),
}

#[derive(Diagnostic, Error, Debug)]
pub enum CreateClientError {
    #[error("Failed to send request: {0}")]
    RequestFailed(#[from] ViturRequestError),
}

#[derive(Diagnostic, Error, Debug)]
pub enum ListClientError {
    #[error("Failed to send request: {0}")]
    RequestFailed(#[from] ViturRequestError),
}

#[derive(Diagnostic, Error, Debug)]
pub enum RevokeClientError {
    #[error("Failed to send request: {0}")]
    RequestFailed(#[from] ViturRequestError),
}

#[derive(Diagnostic, Error, Debug)]
pub enum RetrieveKeyError {
    #[error("Failed to send request: {0}")]
    RequestFailed(#[from] ViturRequestError),
    #[error("Received an invalid number of keys from request. Expected {expected} but received {received}")]
    InvalidNumberOfKeys { expected: usize, received: usize },
}

#[derive(Diagnostic, Error, Debug)]
pub enum GenerateKeyError {
    #[error("Failed to send request: {0}")]
    RequestFailed(#[from] ViturRequestError),
    #[error("Failed to generate IV: {0}")]
    GenerateIv(RecipherError),
    #[error("Received an invalid number of keys from request. Expected {expected} but received {received}")]
    InvalidNumberOfKeys { expected: usize, received: usize },
}

#[derive(Diagnostic, Error, Debug)]
pub enum EncryptError {
    #[error("Failed to generate key: {0}")]
    GenerateKey(#[from] GenerateKeyError),
    #[error("Failed to encrypt: {0}")]
    FailedToEncrypt(aes_gcm_siv::Error),
}

#[derive(Diagnostic, Error, Debug)]
pub enum DecryptError {
    #[error("Failed to retrieve key: {0}")]
    RetrieveKey(#[from] RetrieveKeyError),
    #[error("Failed to decrypt: {0}")]
    FailedToDecrypt(aes_gcm_siv::Error),
    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),
}

#[derive(Diagnostic, Error, Debug)]
pub enum SaveConfigError {
    #[error("Failed to generate new root key: {0}")]
    CreateRootKey(RecipherError),
    #[error("Failed to encrypt root key: {0}")]
    EncryptRootKey(EncryptError),
    #[error("Failed to decrypt root key: {0}")]
    DecryptRootKey(DecryptError),
    #[error("Failed to serialize encrypted root key: {0}")]
    SerializeEncryptedRootKey(serde_cbor::Error),
    #[error("Failed to deserialize encrypted root key: {0}")]
    DeserializeEncryptedRootKey(DecryptError),
    #[error("Invalid index root key length: {0}")]
    InvalidIndexRootKeySize(usize),
    #[error("Failed to send request: {0}")]
    RequestFailed(#[from] ViturRequestError),
}

#[derive(Diagnostic, Error, Debug)]
pub enum LoadConfigError {
    #[error("Failed to decrypt root key: {0}")]
    DecryptRootKey(#[from] DecryptError),
    #[error("Failed to deserialize encrypted root key: {0}")]
    DeserializeEncryptedRootKey(DecryptError),
    #[error("Invalid index root key length: {0}")]
    InvalidIndexRootKeySize(usize),
    #[error("Failed to send request: {0}")]
    RequestFailed(#[from] ViturRequestError),
}

assert_impl_all!(CreateDatasetError: Send, Sync);
assert_impl_all!(ListDatasetError: Send, Sync);
assert_impl_all!(CreateClientError: Send, Sync);
assert_impl_all!(ListClientError: Send, Sync);
assert_impl_all!(RevokeClientError: Send, Sync);
assert_impl_all!(RetrieveKeyError: Send, Sync);
assert_impl_all!(GenerateKeyError: Send, Sync);
assert_impl_all!(EncryptError: Send, Sync);
assert_impl_all!(DecryptError: Send, Sync);
assert_impl_all!(SaveConfigError: Send, Sync);
assert_impl_all!(LoadConfigError: Send, Sync);
