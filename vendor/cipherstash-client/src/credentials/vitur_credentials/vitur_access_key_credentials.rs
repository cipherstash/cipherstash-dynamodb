use std::{path::Path, time::Duration};

use async_mutex::Mutex as AsyncMutex;
use async_trait::async_trait;
use log::debug;
use miette::Diagnostic;
use serde_json::json;
use thiserror::Error;
use url::Url;

use super::vitur_token::ViturToken;
use crate::credentials::{
    token_store::TokenStore, AutoRefreshable, ClearTokenError, Credentials, GetTokenError,
    TokenExpiry,
};
use crate::reqwest_client::create_client;

pub struct ViturAccessKeyCredentials {
    access_key: String,
    console_base_url: Url,
    token_store: AsyncMutex<TokenStore<ViturToken>>,
    client: reqwest_middleware::ClientWithMiddleware,
}

#[derive(Diagnostic, Error, Debug)]
pub enum AcquireTokenError {
    #[error("Failed to acquire token: {0}")]
    RequestFailed(Box<dyn std::error::Error + Sync + Send>),

    #[error("Failed to parse json response: {0}")]
    BadResponse(Box<dyn std::error::Error + Sync + Send>),
}

impl ViturAccessKeyCredentials {
    pub fn new(token_path: &Path, access_key: &str, console_base_url: &Url) -> Self {
        Self {
            access_key: access_key.to_string(),
            console_base_url: console_base_url.to_owned(),
            token_store: AsyncMutex::new(TokenStore::new(token_path)),
            client: create_client(),
        }
    }

    async fn console_authorise_access_token(&self) -> Result<ViturToken, AcquireTokenError> {
        debug!(target: "vitur_access_key_credentials", "Authorising Access Token with Console");

        let url = self.console_base_url.join("/api/authorise").unwrap();

        let token: ViturToken = self
            .client
            .post(url)
            .json(&json!({ "accessKey": self.access_key }))
            .send()
            .await
            .map_err(|e| AcquireTokenError::RequestFailed(Box::new(e)))?
            .error_for_status()
            .map_err(|e| AcquireTokenError::RequestFailed(Box::new(e)))?
            .json()
            .await
            .map_err(|e| AcquireTokenError::BadResponse(Box::new(e)))?;

        debug!(target: "vitur_access_key_credentials",
            "Access Token Acquired - expiry(epoch seconds): {}",
            &token.expiry
        );
        Ok(token)
    }
}

#[async_trait]
impl Credentials for ViturAccessKeyCredentials {
    type Token = ViturToken;

    async fn get_token(&self) -> Result<Self::Token, GetTokenError> {
        debug!(target: "vitur_access_key_credentials", "getting token (waiting for lock)");

        let mut token_store = self.token_store.lock().await;

        debug!(target: "vitur_access_key_credentials", "getting token (got lock)");

        // Check to see if we can get a new token from the cache
        if let Some(cached_token) = token_store.get() {
            debug!(target: "vitur_access_key_credentials", "found cached token");

            // If the token hasn't expired yet just return with it immediately
            if !cached_token.is_expired() {
                debug!(target: "vitur_access_key_credentials", "using cached token");
                return Ok(cached_token);
            }

            debug!(target: "vitur_access_key_credentials", "cached token is expired");
        }

        debug!(target: "vitur_access_key_credentials", "fetching new token from console");

        // The cached token has expired so try and get a new one from console.
        let new_token = self
            .console_authorise_access_token()
            .await
            .map_err(|e| GetTokenError::AcquireNewTokenFailed(Box::new(e)))?;

        // Saves the token to disk
        token_store
            .set(&new_token)
            .map_err(|e| GetTokenError::PersistTokenError(Box::new(e)))?;

        Ok(new_token)
    }

    async fn clear_token(&self) -> Result<(), ClearTokenError> {
        debug!(target: "vitur_access_key_credentials", "clearing token");

        let mut token_store = self.token_store.lock().await;
        token_store
            .clear()
            .map_err(|e| ClearTokenError(Box::new(e)))
    }
}

#[async_trait]
impl AutoRefreshable for ViturAccessKeyCredentials {
    async fn refresh(&self) -> Duration {
        let token = {
            // Drop the guard early to allow other tasks get the current cached token if still valid
            let mut token_store = self.token_store.lock().await;
            token_store.get()
        };

        // Check to see if we have a refresh token from the cache or disk
        if let Some(cached_token) = token {
            debug!(target: "vitur_access_key_credentials", "Found token on disk");

            // If the token is still new, we do an early return
            if !cached_token.should_refresh() {
                debug!(target: "vitur_access_key_credentials", "Access token is still new");
                return cached_token.refresh_interval();
            }
        }

        // The cached token is either missing, or needs a refresh, so try authorising from the access_key
        debug!(target: "vitur_access_key_credentials", "Access token is missing or close to expiry, refreshing");

        if let Ok(new_token) = self.console_authorise_access_token().await {
            let mut token_store = self.token_store.lock().await;
            if token_store.set(&new_token).is_ok() {
                debug!(target: "vitur_access_key_credentials", "Access token refreshed and saved to disk");
                return new_token.refresh_interval();
            }
        }

        Self::Token::min_refresh_interval()
    }
}
