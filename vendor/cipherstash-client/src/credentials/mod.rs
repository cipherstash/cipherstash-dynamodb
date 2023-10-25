pub mod console_credentials;
pub mod token_store;
pub mod vitur_credentials;

#[cfg(feature = "tokio")]
pub mod auto_refresh;

use std::{
    error::Error,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use thiserror::Error;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Expected system time to be greater than UNIX_EPOCH")
        .as_secs()
}

pub trait TokenExpiry<'a>: Clone + Serialize + Deserialize<'a> {
    const EXPIRY_LEEWAY_SECONDS: u64 = 60;
    const REFRESH_LEEWAY_SECONDS: u64 = 180;
    const MIN_REFRESH_INTERVAL_SECONDS: u64 = 10;

    fn expires_at_secs(&self) -> u64;

    fn is_expired(&self) -> bool {
        (now_secs() + Self::EXPIRY_LEEWAY_SECONDS) > self.expires_at_secs()
    }

    fn should_refresh(&self) -> bool {
        (now_secs() + Self::REFRESH_LEEWAY_SECONDS) > self.expires_at_secs()
    }

    fn refresh_interval(&self) -> Duration {
        let threshold = now_secs() + Self::REFRESH_LEEWAY_SECONDS;
        let expires_at = self.expires_at_secs();

        if expires_at > threshold {
            Duration::from_secs(expires_at - threshold)
        } else {
            Duration::from_secs(Self::MIN_REFRESH_INTERVAL_SECONDS)
        }
    }

    fn min_refresh_interval() -> Duration {
        Duration::from_secs(Self::MIN_REFRESH_INTERVAL_SECONDS)
    }
}

#[derive(Diagnostic, Error, Debug)]
pub enum GetTokenError {
    #[error("RefreshTokenFailed: {0}")]
    #[diagnostic(transparent)]
    RefreshTokenFailed(Box<dyn Diagnostic + Send + Sync>),

    #[error("AcquireNewTokenFailed: {0}")]
    #[diagnostic(transparent)]
    AcquireNewTokenFailed(Box<dyn Diagnostic + Send + Sync>),

    #[error("PersistTokenError: {0}")]
    #[diagnostic(transparent)]
    PersistTokenError(Box<dyn Diagnostic + Send + Sync>),
}

#[derive(Error, Debug)]
#[error("RefreshTokenFailed: {0}")]
pub struct ClearTokenError(pub Box<dyn Error>);

#[async_trait]
pub trait Credentials: Send + Sync + 'static {
    type Token;

    async fn get_token(&self) -> Result<Self::Token, GetTokenError>;

    async fn clear_token(&self) -> Result<(), ClearTokenError>;
}

#[async_trait]
pub trait AutoRefreshable: Credentials {
    /// Refresh the token, caches the result, and returns the duration until when the token should refresh again
    async fn refresh(&self) -> Duration;
}
