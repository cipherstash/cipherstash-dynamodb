use crate::encrypted_table::{DeleteError, GetError, InitError, PutError};
use thiserror::Error;

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
}
