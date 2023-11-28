use super::defaults::DEFAULT_VITUR_HOST;
use super::errors::ConfigError;
use super::idp_config::IdpConfig;
use super::vars::{
    CS_CLIENT_ACCESS_KEY, CS_CLIENT_ID, CS_CLIENT_KEY, CS_DECRYPTION_LOG, CS_VITUR_HOST,
    CS_WORKSPACE_ID,
};
use crate::config::{
    console_config::ConsoleConfig, paths::resolve_config_dir, workspace::resolve_workspace,
};
use crate::credentials::vitur_credentials::{
    ViturAccessKeyCredentials, ViturConsoleAuthCredentials, ViturCredentials,
};
use crate::vitur::{Vitur, ViturWithClientKey};
use std::path::PathBuf;
use url::Url;
use vitur_client::ClientKey;

#[derive(Default)]
pub struct ViturConfigBuilder {
    config_dir: Option<String>,
    base_url: Option<String>,
    workspace_id: Option<String>,
    decryption_log: Option<bool>,

    // auth
    access_key: Option<String>,
    console_config: Option<ConsoleConfig>,
    idp_config: Option<IdpConfig>,

    // client key/id
    client_id: Option<String>,
    client_key: Option<String>,
}

impl ViturConfigBuilder {
    pub fn build(&self) -> Result<ViturConfig, ConfigError> {
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

        let workspace_id = resolve_workspace(&config_dir, &self.workspace_id)
            .ok_or(ConfigError::ValueNotSet("workspace_id"))?;

        let workspace_dir = config_dir.join(&workspace_id);
        std::fs::create_dir_all(workspace_dir).map_err(|e| {
            ConfigError::Io(
                e.to_string(),
                config_dir.to_str().unwrap_or("Unknown").to_string(),
            )
        })?;

        let base_url = self
            .base_url
            .to_owned()
            .unwrap_or(DEFAULT_VITUR_HOST.to_string())
            .parse::<Url>()?;

        let auth_config = self.build_auth_config()?;

        let decryption_log = self.decryption_log.unwrap_or(false);

        Ok(ViturConfig {
            config_dir,
            base_url,
            workspace_id,
            auth_config,
            decryption_log,
            client_key: (),
        })
    }

    pub fn build_auth_config(&self) -> Result<ViturAuthConfig, ConfigError> {
        let console_config = match &self.console_config {
            Some(c) => c.to_owned(),
            None => ConsoleConfig::builder()
                .set_config_dir(&self.config_dir)
                .build()?,
        };

        let idp_config: IdpConfig = match &self.idp_config {
            Some(c) => c.to_owned(),
            None => IdpConfig::builder().build()?,
        };

        let auth_config = if let Some(access_key) = &self.access_key {
            ViturAuthConfig::AccessKey {
                access_key: access_key.to_string(),
                idp_config,
            }
        } else {
            ViturAuthConfig::ConsoleAuth {
                idp_config,
                console_config,
            }
        };

        Ok(auth_config)
    }

    pub fn build_with_client_key(&self) -> Result<ViturConfigWithClientKey, ConfigError> {
        let base_config = self.build()?;

        let client_id = self
            .client_id
            .to_owned()
            .ok_or(ConfigError::ValueNotSet("Client ID"))?;

        let client_key = {
            let key_hex = self
                .client_key
                .to_owned()
                .ok_or(ConfigError::ValueNotSet("Client Key"))?;

            let key_bytes = hex::decode(key_hex)
                .map_err(|_| ConfigError::InvalidConfigError("Invalid Client Key".into()))?;

            ClientKey::from_bytes(&client_id, &key_bytes)
                .map_err(|_| ConfigError::InvalidConfigError("Invalid Client Key".into()))?
        };

        Ok(ViturConfig::<ClientKey> {
            config_dir: base_config.config_dir,
            base_url: base_config.base_url,
            workspace_id: base_config.workspace_id,
            auth_config: base_config.auth_config,
            decryption_log: base_config.decryption_log,
            client_key,
        })
    }

    pub fn access_key(mut self, value: &str) -> Self {
        self.access_key = Some(value.to_string());
        self
    }

    pub fn base_url(mut self, value: &str) -> Self {
        self.base_url = Some(value.to_string());
        self
    }

    pub fn config_dir(mut self, value: &str) -> Self {
        self.config_dir = Some(value.to_owned());
        self
    }

    pub fn console_config(mut self, value: &ConsoleConfig) -> Self {
        self.console_config = Some(value.to_owned());
        self
    }

    pub fn idp_config(mut self, value: &IdpConfig) -> Self {
        self.idp_config = Some(value.to_owned());
        self
    }

    pub fn workspace_id(mut self, value: &str) -> Self {
        self.workspace_id = Some(value.to_owned());
        self
    }

    pub fn decryption_log(mut self, value: bool) -> Self {
        self.decryption_log = Some(value);
        self
    }

    pub fn client_id(mut self, value: &str) -> Self {
        self.client_id = Some(value.to_owned());
        self
    }

    pub fn client_key(mut self, value: &str) -> Self {
        self.client_key = Some(value.to_owned());
        self
    }

    pub fn with_env(mut self) -> Self {
        if let Ok(value) = std::env::var(CS_VITUR_HOST) {
            self.base_url = Some(value);
        }

        if let Ok(value) = std::env::var(CS_CLIENT_ACCESS_KEY) {
            self.access_key = Some(value);
        }

        if let Ok(value) = std::env::var(CS_WORKSPACE_ID) {
            self.workspace_id = Some(value);
        }

        if let Ok(value) = std::env::var(CS_DECRYPTION_LOG) {
            self.decryption_log = Some(value.to_lowercase() == *"true");
        }

        if let Ok(client_id) = std::env::var(CS_CLIENT_ID) {
            self.client_id = Some(client_id);
        }

        if let Ok(client_key) = std::env::var(CS_CLIENT_KEY) {
            self.client_key = Some(client_key);
        }

        self
    }

    pub fn with_config(
        mut self,
        client_id: &str,
        client_secret: &str,
        workspace_id: &str,
        client_access_key: &str,
    ) -> Self {
        self.client_id = Some(client_id.to_owned());
        self.client_key = Some(client_secret.to_owned());
        self.workspace_id = Some(workspace_id.to_owned());
        self.access_key = Some(client_access_key.to_owned());

        self
    }
}

#[derive(Clone)]
pub enum ViturAuthConfig {
    AccessKey {
        access_key: String,
        idp_config: IdpConfig,
    },
    ConsoleAuth {
        console_config: ConsoleConfig,
        idp_config: IdpConfig,
    },
}

#[derive(Clone)]
pub struct ViturConfig<ClientKeyState = ()> {
    config_dir: PathBuf,
    base_url: Url,
    workspace_id: String,
    auth_config: ViturAuthConfig,
    decryption_log: bool,
    client_key: ClientKeyState,
}

pub type ViturConfigWithClientKey = ViturConfig<ClientKey>;

impl ViturConfig {
    pub fn builder() -> ViturConfigBuilder {
        ViturConfigBuilder::default()
    }

    pub fn create_vitur(&self) -> Vitur<ViturCredentials> {
        Vitur::new(
            &self.base_url,
            self.credentials(),
            self.decryption_log_path().as_deref(),
        )
    }
}

impl ViturConfigWithClientKey {
    pub fn client_key(&self) -> ClientKey {
        self.client_key.clone()
    }

    pub fn create_vitur(&self) -> ViturWithClientKey<ViturCredentials> {
        Vitur::new_with_client_key(
            &self.base_url,
            self.credentials(),
            self.decryption_log_path().as_deref(),
            self.client_key(),
        )
    }
}

impl<T> ViturConfig<T> {
    pub fn workspace_dir(&self) -> PathBuf {
        self.config_dir.join(&self.workspace_id)
    }

    pub fn token_path(&self) -> PathBuf {
        let token_file = match self.auth_config {
            ViturAuthConfig::AccessKey { .. } => "vitur-access-key-auth.json",
            ViturAuthConfig::ConsoleAuth { .. } => "vitur-console-auth.json",
        };

        self.config_dir.join(&self.workspace_id).join(token_file)
    }

    pub fn decryption_log_path(&self) -> Option<PathBuf> {
        self.decryption_log.then_some(
            self.config_dir
                .join(&self.workspace_id)
                .join("decryptions.log"),
        )
    }

    pub fn base_url(&self) -> Url {
        self.base_url.to_owned()
    }

    pub fn credentials(&self) -> ViturCredentials {
        match &self.auth_config {
            ViturAuthConfig::AccessKey {
                access_key,
                idp_config,
            } => {
                let creds = ViturAccessKeyCredentials::new(
                    &self.token_path(),
                    access_key,
                    &idp_config.base_url(),
                );
                ViturCredentials::AccessKey(creds)
            }
            ViturAuthConfig::ConsoleAuth {
                console_config,
                idp_config,
            } => {
                let creds = ViturConsoleAuthCredentials::new(
                    &self.token_path(),
                    console_config.credentials(),
                    &idp_config.base_url(),
                    &self.workspace_id,
                );
                ViturCredentials::ConsoleAuth(creds)
            }
        }
    }
}
