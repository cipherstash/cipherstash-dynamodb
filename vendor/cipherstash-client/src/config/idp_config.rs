use url::Url;

use super::defaults::DEFAULT_VITUR_IDP_BASE_URL;
use super::errors::ConfigError;
use super::vars::CS_VITUR_IDP_HOST;

pub struct IdpConfigBuilder {
    base_url: String,
}

impl Default for IdpConfigBuilder {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_VITUR_IDP_BASE_URL.to_string(),
        }
    }
}

impl IdpConfigBuilder {
    pub fn with_env(mut self) -> Self {
        if let Ok(value) = std::env::var(CS_VITUR_IDP_HOST) {
            self.base_url = value;
        }

        self
    }

    pub fn build(self) -> Result<IdpConfig, ConfigError> {
        Ok(IdpConfig {
            base_url: self.base_url.parse()?,
        })
    }

    pub fn base_url(mut self, value: &str) -> Self {
        self.base_url = value.to_string();
        self
    }
}

#[derive(Clone)]
pub struct IdpConfig {
    base_url: Url,
}

impl IdpConfig {
    pub fn builder() -> IdpConfigBuilder {
        IdpConfigBuilder::default()
    }

    pub fn base_url(&self) -> Url {
        self.base_url.clone()
    }
}

#[cfg(test)]
mod tests {
    use sealed_test::prelude::*;

    use super::*;

    #[sealed_test]
    fn test_with_default_values() {
        let default_base_url: Url = DEFAULT_VITUR_IDP_BASE_URL.parse().unwrap();
        let idp_config = IdpConfig::builder().build().unwrap();

        assert_eq!(idp_config.base_url(), default_base_url);
    }

    #[sealed_test]
    fn test_with_env_fallbacks_to_default_values() {
        std::env::remove_var(CS_VITUR_IDP_HOST);

        let default_base_url: Url = DEFAULT_VITUR_IDP_BASE_URL.parse().unwrap();
        let idp_config = IdpConfig::builder().with_env().build().unwrap();

        assert_eq!(idp_config.base_url(), default_base_url);
    }

    #[sealed_test]
    fn test_with_env_values() {
        std::env::set_var(
            CS_VITUR_IDP_HOST,
            "https://custom-idp.from-env.cipherstash.com",
        );

        let env_base_url: Url = "https://custom-idp.from-env.cipherstash.com"
            .parse()
            .unwrap();
        let idp_config = IdpConfig::builder().with_env().build().unwrap();

        assert_eq!(idp_config.base_url(), env_base_url);
    }

    #[sealed_test]
    fn test_with_override() {
        std::env::set_var(
            CS_VITUR_IDP_HOST,
            "https://custom-idp.from-env.cipherstash.com",
        );

        let override_base_url: Url = "https://custom-idp.from-override.cipherstash.com"
            .parse()
            .unwrap();
        let idp_config = IdpConfig::builder()
            .with_env()
            .base_url("https://custom-idp.from-override.cipherstash.com")
            .build()
            .unwrap();

        assert_eq!(idp_config.base_url(), override_base_url);
    }
}
