pub mod vitur_access_key_credentials;
pub mod vitur_console_auth_credentials;
pub mod vitur_token;

use std::time::Duration;

use async_trait::async_trait;

pub use vitur_access_key_credentials::ViturAccessKeyCredentials;
pub use vitur_console_auth_credentials::ViturConsoleAuthCredentials;
pub use vitur_token::ViturToken;

use super::{
    console_credentials::ConsoleCredentials, AutoRefreshable, ClearTokenError, Credentials,
    GetTokenError,
};

pub enum ViturCredentials {
    AccessKey(ViturAccessKeyCredentials),
    ConsoleAuth(ViturConsoleAuthCredentials<ConsoleCredentials>),
}

#[async_trait]
impl Credentials for ViturCredentials {
    type Token = ViturToken;

    async fn get_token(&self) -> Result<Self::Token, GetTokenError> {
        match self {
            ViturCredentials::AccessKey(ak) => ak.get_token().await,
            ViturCredentials::ConsoleAuth(c) => c.get_token().await,
        }
    }

    async fn clear_token(&self) -> Result<(), ClearTokenError> {
        match self {
            ViturCredentials::AccessKey(ak) => ak.clear_token().await,
            ViturCredentials::ConsoleAuth(c) => c.clear_token().await,
        }
    }
}

#[async_trait]
impl AutoRefreshable for ViturCredentials {
    async fn refresh(&self) -> Duration {
        match self {
            ViturCredentials::AccessKey(ak) => ak.refresh().await,
            ViturCredentials::ConsoleAuth(c) => c.refresh().await,
        }
    }
}
