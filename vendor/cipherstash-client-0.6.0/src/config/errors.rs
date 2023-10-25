use miette::Diagnostic;
use thiserror::Error;

use crate::vitur::errors::LoadConfigError;

/// Errors that occur while building or loading config.
#[derive(Error, Debug, Diagnostic)]
pub enum ConfigError {
    #[error("ConfigError - Value [{0}] was not set")]
    ValueNotSet(&'static str),

    #[error("IO Error: file = {1} {0}")]
    Io(String, String),

    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    /// Errors caused by invalid configuration provided by the user.
    #[error("Invalid config error: {0}")]
    InvalidConfigError(String),

    #[diagnostic(transparent)]
    #[error(transparent)]
    LoadConfigError(#[from] LoadConfigError),

    /// Error caused when the home directory can't be resolved
    #[error("{0}")]
    HomeDirError(String),
}
