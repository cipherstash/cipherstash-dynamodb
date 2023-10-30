use thiserror::Error;
use crate::encrypted_table::{InitError, PutError, GetError, DeleteError};

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