use std::path::PathBuf;

use url::Url;

use crate::{
    config::paths::resolve_config_dir, credentials::console_credentials::ConsoleCredentials,
};

use super::{
    defaults::{
        DEFAULT_CONSOLE_BASE_URL, DEFAULT_CONSOLE_IDP_AUDIENCE, DEFAULT_CONSOLE_IDP_BASE_URL,
        DEFAULT_CONSOLE_IDP_CLIENT_ID,
    },
    errors::ConfigError,
    vars::{CS_CONSOLE_HOST, CS_IDP_AUDIENCE, CS_IDP_CLIENT_ID, CS_IDP_HOST},
};

#[derive(Debug, Clone)]
pub struct ConsoleConfigBuilder {
    config_dir: Option<String>,
    base_url: String,

    // auth
    idp_audience: String,
    idp_base_url: String,
    idp_client_id: String,
}

impl Default for ConsoleConfigBuilder {
    fn default() -> Self {
        Self {
            config_dir: None,
            base_url: DEFAULT_CONSOLE_BASE_URL.to_string(),
            idp_audience: DEFAULT_CONSOLE_IDP_AUDIENCE.to_string(),
            idp_base_url: DEFAULT_CONSOLE_IDP_BASE_URL.to_string(),
            idp_client_id: DEFAULT_CONSOLE_IDP_CLIENT_ID.to_string(),
        }
    }
}

impl ConsoleConfigBuilder {
    pub fn build(&self) -> Result<ConsoleConfig, ConfigError> {
        let config_dir = match &self.config_dir {
            Some(s) => std::path::PathBuf::from(s),
            None => resolve_config_dir(None).map_err(|_| ConfigError::ValueNotSet("config_dir"))?,
        };
        std::fs::create_dir_all(&config_dir).map_err(|e| {
            ConfigError::Io(
                e.to_string(),
                config_dir.to_str().unwrap_or("Unknown").to_string(),
            )
        })?;

        Ok(ConsoleConfig {
            config_dir,
            base_url: Box::new(self.base_url.parse()?),
            idp_base_url: Box::new(self.idp_base_url.parse()?),
            idp_client_id: self.idp_client_id.to_string(),
            idp_audience: self.idp_audience.to_string(),
        })
    }

    pub fn config_dir(mut self, value: &str) -> Self {
        self.config_dir = Some(value.to_string());
        self
    }

    pub fn set_config_dir(mut self, value: &Option<String>) -> Self {
        self.config_dir = value.to_owned();
        self
    }

    pub fn base_url(mut self, value: &str) -> Self {
        self.base_url = value.to_string();
        self
    }

    pub fn idp_audience(mut self, value: &str) -> Self {
        self.idp_audience = value.to_string();
        self
    }

    pub fn idp_base_url(mut self, value: &str) -> Self {
        self.idp_base_url = value.to_string();
        self
    }

    pub fn idp_client_id(mut self, value: &str) -> Self {
        self.idp_client_id = value.to_string();
        self
    }

    pub fn with_env(mut self) -> Self {
        if let Ok(value) = std::env::var(CS_CONSOLE_HOST) {
            self.base_url = value;
        }

        if let Ok(value) = std::env::var(CS_IDP_AUDIENCE) {
            self.idp_audience = value;
        }

        if let Ok(value) = std::env::var(CS_IDP_HOST) {
            self.idp_base_url = value;
        }

        if let Ok(value) = std::env::var(CS_IDP_CLIENT_ID) {
            self.idp_client_id = value;
        }

        self
    }
}

#[derive(Clone)]
pub struct ConsoleConfig {
    config_dir: PathBuf,
    base_url: Box<Url>,

    // auth
    idp_audience: String,
    idp_base_url: Box<Url>,
    idp_client_id: String,
}

impl ConsoleConfig {
    pub fn builder() -> ConsoleConfigBuilder {
        ConsoleConfigBuilder::default()
    }

    pub fn config_dir(&self) -> PathBuf {
        self.config_dir.to_owned()
    }

    pub fn token_path(&self) -> PathBuf {
        self.config_dir.join("console-auth.json")
    }

    pub fn base_url(&self) -> Url {
        *self.base_url.to_owned()
    }

    pub fn credentials(&self) -> ConsoleCredentials {
        ConsoleCredentials::new(
            &self.token_path(),
            &self.idp_base_url,
            &self.idp_audience,
            &self.idp_client_id,
        )
    }
}
