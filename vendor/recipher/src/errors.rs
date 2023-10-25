use thiserror::Error;

#[derive(Error, Debug)]
pub enum RecipherError {
    #[error("randomization error `{0}`")]
    RandomizationError(String),

    #[error("Serialization error")]
    Serialization(#[from] serde_cbor::Error),
}
