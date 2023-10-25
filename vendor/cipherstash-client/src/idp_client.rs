use crate::{
    credentials::{console_credentials::ConsoleToken, Credentials, GetTokenError},
    reqwest_client::create_client,
};
use miette::Diagnostic;
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessKey {
    pub key_id: String,
    pub workspace_id: String,
    pub key_name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateAccessKeyInput {
    workspace_id: String,
    key_name: String,
}

#[derive(Diagnostic, Error, Debug)]
pub enum CreateAccessKeyError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),

    #[error(transparent)]
    Credentials(#[from] GetTokenError),
}

#[derive(Diagnostic, Error, Debug)]
pub enum ListAccessKeysError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),

    #[error(transparent)]
    Credentials(#[from] GetTokenError),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RevokeAccessKeyInput {
    workspace_id: String,
    key_name: String,
}

#[derive(Diagnostic, Error, Debug)]
pub enum RevokeAccessKeyError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),

    #[error(transparent)]
    Credentials(#[from] GetTokenError),
}

#[derive(Debug, Deserialize)]
struct RevokeAccessKeyResponse {
    message: String,
}

pub struct IdpClient<C: Credentials<Token = ConsoleToken>> {
    client: ClientWithMiddleware,
    base_url: Url,
    credentials: C,
}

impl<C> IdpClient<C>
where
    C: Credentials<Token = ConsoleToken>,
{
    pub fn new(base_url: Url, credentials: C) -> Self {
        let client = create_client();

        Self {
            client,
            base_url,
            credentials,
        }
    }

    pub async fn create_access_key(
        &self,
        name: &str,
        workspace_id: &str,
    ) -> Result<String, CreateAccessKeyError> {
        let url = self.base_url.join("/api/access-key").expect("Invalid url");

        let console_token = self.credentials.get_token().await?;

        let body = CreateAccessKeyInput {
            workspace_id: workspace_id.into(),
            key_name: name.into(),
        };

        let response = self
            .client
            .post(url)
            .header("authorization", console_token.as_header())
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        let access_key: String = response.text().await?;

        Ok(access_key)
    }

    pub async fn list_access_keys(
        &self,
        workspace_id: &Option<String>,
    ) -> Result<Vec<AccessKey>, ListAccessKeysError> {
        let endpoint = match &workspace_id {
            None => "/api/access-keys".to_string(),
            Some(workspace_id) => format!("/api/access-keys/{workspace_id}"),
        };

        let url = self.base_url.join(&endpoint).expect("Invalid url");

        let console_token = self.credentials.get_token().await?;

        let response = self
            .client
            .get(url)
            .header("authorization", console_token.as_header())
            .send()
            .await?
            .error_for_status()?;

        let access_keys: Vec<AccessKey> = response.json().await?;

        Ok(access_keys)
    }

    pub async fn revoke_access_key(
        &self,
        name: &str,
        workspace_id: &str,
    ) -> Result<String, RevokeAccessKeyError> {
        let url = self.base_url.join("/api/access-key").expect("Invalid url");

        let console_token = self.credentials.get_token().await?;

        let body = RevokeAccessKeyInput {
            workspace_id: workspace_id.into(),
            key_name: name.into(),
        };

        let response = self
            .client
            .delete(url)
            .header("authorization", console_token.as_header())
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        let revoke_ak_response: RevokeAccessKeyResponse = response.json().await?;

        Ok(revoke_ak_response.message)
    }
}
