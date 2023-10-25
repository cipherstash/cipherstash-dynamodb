use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_mutex::Mutex as AsyncMutex;
use async_trait::async_trait;
use log::debug;
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use url::Url;

use super::{
    token_store::TokenStore, AutoRefreshable, ClearTokenError, Credentials, GetTokenError,
    TokenExpiry,
};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Expected system time to be greater than UNIX_EPOCH")
        .as_secs()
}

#[derive(Deserialize)]
struct AccessTokenResponse {
    refresh_token: String,
    access_token: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct PollingInfo {
    user_code: String,
    device_code: String,
    verification_uri_complete: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleToken {
    refresh_token: String,
    access_token: String,
    expiry: u64,
}

impl ConsoleToken {
    pub fn access_token(&self) -> String {
        self.access_token.to_string()
    }

    pub fn as_header(&self) -> String {
        format!("Bearer {}", self.access_token)
    }
}

impl<'a> TokenExpiry<'a> for ConsoleToken {
    fn expires_at_secs(&self) -> u64 {
        self.expiry
    }
}

impl From<AccessTokenResponse> for ConsoleToken {
    fn from(value: AccessTokenResponse) -> Self {
        Self {
            access_token: value.access_token,
            refresh_token: value.refresh_token,
            expiry: value.expires_in + now_secs(),
        }
    }
}

#[derive(Diagnostic, Error, Debug)]
pub enum RefreshTokenError {
    #[error("Failed to redeem refresh token: {0}")]
    RequestFailed(reqwest::Error),

    #[error("Failed to parse json response: {0}")]
    BadResponse(reqwest::Error),
}

#[derive(Diagnostic, Error, Debug)]
pub enum NewTokenError {
    #[error("Failed to get auth0 device code: {0}")]
    DeviceCodeRequestFailed(reqwest::Error),

    #[error("Failed to parse polling info json response: {0}")]
    DeviceCodeBadResponse(reqwest::Error),

    #[error("Failed to poll for new token: {0}")]
    PollTokenRequestFailed(reqwest::Error),

    #[error("Failed to parse access token response: {0}")]
    PollTokenBadResponse(reqwest::Error),

    #[error("Failed to parse pending auth response: {0}")]
    PollTokenBadPendingResponse(reqwest::Error),

    #[error("Device code authentication failed: {0}")]
    PollTokenAuthFailed(String),

    #[error("Unexpected error code in response body: {0}")]
    PollTokenUnexpected(String),
}

async fn sleep(duration: &Duration) {
    cfg_if::cfg_if! {
        if #[cfg(feature = "tokio")] {
            tokio::time::sleep(*duration).await
        } else {
            std::thread::sleep(*duration)
        }
    }
}

#[derive(Debug)]
pub struct ConsoleCredentials {
    idp_base_url: Url,
    idp_audience: String,
    idp_client_id: String,
    token_store: AsyncMutex<TokenStore<ConsoleToken>>,
}

impl ConsoleCredentials {
    pub fn new(
        token_path: &Path,
        idp_base_url: &Url,
        idp_audience: &str,
        idp_client_id: &str,
    ) -> Self {
        let token_store = AsyncMutex::new(TokenStore::new(token_path));

        Self {
            idp_base_url: idp_base_url.to_owned(),
            idp_audience: idp_audience.to_string(),
            idp_client_id: idp_client_id.to_string(),
            token_store,
        }
    }

    /// Poll the IDP until it returns an access token or fails
    async fn poll_access_token(
        &self,
        client: &reqwest::Client,
        polling_info: &PollingInfo,
    ) -> Result<ConsoleToken, NewTokenError> {
        debug!(target: "console_credentials", "Logging in - polling for access token");
        let mut interval = Duration::from_secs(5);
        let url = self.idp_base_url.join("oauth/token").expect("Invalid url");

        loop {
            let response = client
                .post(url.to_owned())
                .json(&json!({
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": polling_info.device_code,
                    "client_id": self.idp_client_id
                }))
                .send()
                .await
                .map_err(NewTokenError::PollTokenRequestFailed)?;

            match response.status().as_u16() {
                200 => {
                    let token: AccessTokenResponse = response
                        .json()
                        .await
                        .map_err(NewTokenError::PollTokenBadResponse)?;

                    debug!(target: "console_credentials",
                        "Access Token Acquired - expires_in(s): {}",
                        &token.expires_in
                    );
                    return Ok(token.into());
                }
                403 => {
                    #[derive(Deserialize, Debug)]
                    #[serde(rename_all = "snake_case")]
                    enum AuthError {
                        AuthorizationPending,
                        SlowDown,
                        InvalidGrant,
                        AccessDenied,
                        ExpiredToken,
                    }

                    #[derive(Deserialize)]
                    struct PendingResponse {
                        error: AuthError,
                        error_description: Option<String>,
                    }

                    let PendingResponse {
                        error,
                        error_description,
                    } = response
                        .json()
                        .await
                        .map_err(NewTokenError::PollTokenBadPendingResponse)?;

                    match error {
                        AuthError::AuthorizationPending => {}
                        AuthError::SlowDown => {
                            interval += Duration::from_secs(5);
                        }
                        _ => {
                            let reason = error_description.unwrap_or(format!("{error:?}"));
                            return Err(NewTokenError::PollTokenAuthFailed(reason));
                        }
                    }

                    sleep(&interval).await
                }
                code => {
                    return Err(NewTokenError::PollTokenUnexpected(format!(
                        "Unexpected response code: {code}"
                    )));
                }
            }
        }
    }

    /// Show a prompt in the terminal and open a browser (if available) with an authentication link for generating
    /// an access token.
    fn prompt_user(polling_info: &PollingInfo) {
        if open::that(&polling_info.verification_uri_complete).is_err() {
            println!("Failed to open web browser. Please manually click the link in the following message.")
        }

        let user_code = &polling_info.user_code;
        let code_len = user_code.len();

        println!();
        println!("### ACTION REQUIRED ###");
        println!();
        println!(
            "Visit {} to complete authentication by following the below steps:",
            polling_info.verification_uri_complete
        );
        println!();
        println!("1. Verify that this code matches the code in your browser");
        println!();
        println!("             +------{}------+", "-".repeat(code_len));
        println!("             |      {}      |", " ".repeat(code_len));
        println!("             |      {user_code}      |");
        println!("             |      {}      |", " ".repeat(code_len));
        println!("             +------{}------+", "-".repeat(code_len));
        println!();
        println!("2. If the codes match, click on the confirm button in the browser");
        println!();
        println!("Waiting for authentication...");
    }

    async fn acquire_new_token(&self) -> Result<ConsoleToken, NewTokenError> {
        debug!(target: "console_credentials", "Logging in...");
        let client = reqwest::Client::new();
        let url = self
            .idp_base_url
            .join("oauth/device/code")
            .expect("Invalid url");

        let info_response = client
            .post(url)
            .json(&json!({
                "audience": &self.idp_audience,
                "client_id": &self.idp_client_id,
                "scope": "offline_access",
            }))
            .send()
            .await
            .map_err(NewTokenError::DeviceCodeRequestFailed)?
            .error_for_status()
            .map_err(NewTokenError::DeviceCodeRequestFailed)?;

        let polling_info: PollingInfo = info_response
            .json()
            .await
            .map_err(NewTokenError::DeviceCodeBadResponse)?;

        Self::prompt_user(&polling_info);

        self.poll_access_token(&client, &polling_info).await
    }

    async fn refresh_access_token(
        &self,
        cached_token: &ConsoleToken,
    ) -> Result<Option<ConsoleToken>, RefreshTokenError> {
        debug!(target: "console_credentials", "Refreshing Access Token...");
        let client = reqwest::Client::new();
        let url = self.idp_base_url.join("oauth/token").expect("Invalid url");

        let response = client
            .post(url)
            .json(&json!({
                "grant_type": "refresh_token",
                "refresh_token": cached_token.refresh_token,
                "client_id": self.idp_client_id,
                "scope": "offline_access",
            }))
            .send()
            .await
            .map_err(RefreshTokenError::RequestFailed)?;

        if let Ok(r) = response.error_for_status() {
            let response: AccessTokenResponse =
                r.json().await.map_err(RefreshTokenError::BadResponse)?;
            debug!(target: "console_credentials",
                "Access Token Acquired - expires_in(s): {}",
                &response.expires_in
            );

            Ok(Some(response.into()))
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
impl Credentials for ConsoleCredentials {
    type Token = ConsoleToken;

    async fn get_token(&self) -> Result<Self::Token, GetTokenError> {
        let mut token_store = self.token_store.lock().await;

        // Check to see if we can make a new token from the cache
        if let Some(cached_token) = &token_store.get() {
            // If the token hasn't expired yet just return with it immediately
            if !cached_token.is_expired() {
                return Ok(cached_token.clone());
            }

            // The cached token has expired so try and get a new one from the refresh token.
            // If auto refresh is enabled, this should not have to happen
            if let Some(new_token) = self
                .refresh_access_token(cached_token)
                .await
                .map_err(|e| GetTokenError::RefreshTokenFailed(Box::new(e)))?
            {
                token_store
                    .set(&new_token)
                    .map_err(|e| GetTokenError::PersistTokenError(Box::new(e)))?;
                return Ok(new_token);
            }
        }

        // We need to ask the user to allow us to get a new token via device code
        let new_token = self
            .acquire_new_token()
            .await
            .map_err(|err| GetTokenError::AcquireNewTokenFailed(Box::new(err)))?;

        // Saves the token to disk
        token_store
            .set(&new_token)
            .map_err(|e| GetTokenError::PersistTokenError(Box::new(e)))?;
        Ok(new_token)
    }

    async fn clear_token(&self) -> Result<(), ClearTokenError> {
        let mut token_store = self.token_store.lock().await;
        token_store
            .clear()
            .map_err(|e| ClearTokenError(Box::new(e)))
    }
}

#[async_trait]
impl AutoRefreshable for ConsoleCredentials {
    async fn refresh(&self) -> Duration {
        let token = {
            // Drop the guard early to allow other tasks get the current cached token if still valid
            let mut token_store = self.token_store.lock().await;
            token_store.get()
        };

        // Check to see if we have a token from the cache or disk
        if let Some(cached_token) = token {
            debug!(target: "console_credentials", "Found token on disk");

            // If the token is still new, we do an early return
            if !cached_token.should_refresh() {
                debug!(target: "console_credentials", "Access token is still new");
                return cached_token.refresh_interval();
            }

            // The cached token is close to expiry, so try and get a new one from the refresh token
            debug!(target: "console_credentials", "Access token close to expiry, refreshing");
            if let Ok(Some(new_token)) = self.refresh_access_token(&cached_token).await {
                let mut token_store = self.token_store.lock().await;
                if token_store.set(&new_token).is_ok() {
                    debug!(target: "console_credentials", "Access token refreshed and saved to disk");
                    return new_token.refresh_interval();
                }
            }
        }

        Self::Token::min_refresh_interval()
    }
}
