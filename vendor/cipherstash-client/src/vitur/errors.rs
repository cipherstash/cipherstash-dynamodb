use miette::Diagnostic;
use thiserror::Error;

use crate::credentials::GetTokenError;
use vitur_protocol::*;

#[derive(Error, Debug, Diagnostic)]
pub enum CreateDatasetError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    CredentialsError(#[from] GetTokenError),

    #[error(transparent)]
    ViturError(#[from] vitur_client::CreateDatasetError),
}

#[derive(Error, Debug, Diagnostic)]
pub enum ListDatasetError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    CredentialsError(#[from] GetTokenError),

    #[error(transparent)]
    ViturError(#[from] vitur_client::ListDatasetError),
}

#[derive(Error, Debug, Diagnostic)]
pub enum EnableDatasetError {
    #[error(transparent)]
    CredentialsError(#[from] GetTokenError),

    #[error(transparent)]
    ViturError(#[from] vitur_client::EnableDatasetError),
}

#[derive(Error, Debug, Diagnostic)]
pub enum ModifyDatasetError {
    #[error(transparent)]
    CredentialsError(#[from] GetTokenError),

    #[error(transparent)]
    ViturError(#[from] vitur_client::ModifyDatasetError),
}

#[derive(Error, Debug, Diagnostic)]
pub enum DisableDatasetError {
    #[error(transparent)]
    CredentialsError(#[from] GetTokenError),

    #[error(transparent)]
    ViturError(#[from] vitur_client::DisableDatasetError),
}

#[derive(Error, Debug, Diagnostic)]
pub enum CreateClientError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    CredentialsError(#[from] GetTokenError),

    #[error(transparent)]
    ViturError(#[from] vitur_client::CreateClientError),
}

#[derive(Error, Debug, Diagnostic)]
pub enum ListClientError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    CredentialsError(#[from] GetTokenError),

    #[error(transparent)]
    ViturError(#[from] vitur_client::ListClientError),
}

#[derive(Error, Debug, Diagnostic)]
pub enum RevokeClientError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    CredentialsError(#[from] GetTokenError),

    #[error(transparent)]
    ViturError(#[from] vitur_client::RevokeClientError),
}

#[derive(Error, Debug, Diagnostic)]
pub enum SaveConfigError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    CredentialsError(#[from] GetTokenError),

    #[error(transparent)]
    ViturError(#[from] vitur_client::SaveConfigError),
}

#[derive(Error, Debug, Diagnostic)]
pub enum LoadConfigError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    CredentialsError(#[from] GetTokenError),

    #[diagnostic(help("have you tried uploading a config using stash cli?"))]
    #[error("Could not find dataset config")]
    MissingConfig,

    #[error(transparent)]
    ViturError(vitur_client::LoadConfigError),
}

impl From<vitur_client::LoadConfigError> for LoadConfigError {
    fn from(value: vitur_client::LoadConfigError) -> Self {
        if let vitur_client::LoadConfigError::RequestFailed(ViturRequestError {
            kind: ViturRequestErrorKind::NotFound,
            ..
        }) = value
        {
            Self::MissingConfig
        } else {
            Self::ViturError(value)
        }
    }
}

#[derive(Error, Debug, Diagnostic)]
pub enum DecryptError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    CredentialsError(#[from] GetTokenError),

    #[error(transparent)]
    ViturError(#[from] vitur_client::DecryptError),
}

#[derive(Error, Debug, Diagnostic)]
pub enum EncryptError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    CredentialsError(#[from] GetTokenError),

    #[error(transparent)]
    ViturError(#[from] vitur_client::EncryptError),
}
