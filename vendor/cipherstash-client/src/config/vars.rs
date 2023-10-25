//! This module defines all of the environment variables
//! used by `cipherstash-client`.

/// Specifies the base URL for Vitur
/// e.g. http://localhost:3000
pub static CS_VITUR_HOST: &str = "CS_VITUR_HOST";

/// Specifies the base URL for console
/// e.g. https://dev.console.cipherstash.com
pub static CS_CONSOLE_HOST: &str = "CS_CONSOLE_HOST";

/// Specifies the request audience for console tokens
/// e.g. http://console.cipherstash.com
pub static CS_IDP_AUDIENCE: &str = "CS_IDP_AUDIENCE";

/// Specifies the IDP host to use for authentication against Console
/// e.g. https://auth.cipherstash.com
pub static CS_IDP_HOST: &str = "CS_IDP_HOST";

/// Specifies the IDP client ID
/// e.g. fkjhfw4euwkuyfkw4uhfkuyi284e1k
pub static CS_IDP_CLIENT_ID: &str = "CS_IDP_CLIENT_ID";

/// Specifies the IDP host to use for authentication against Vitur
/// e.g. https://console.cipherstash.com
pub static CS_VITUR_IDP_HOST: &str = "CS_VITUR_IDP_HOST";

/// Specifies the Vitur client ID
pub static CS_CLIENT_ID: &str = "CS_CLIENT_ID";

/// Specifies the Vitur client Key
pub static CS_CLIENT_KEY: &str = "CS_CLIENT_KEY";

/// Specifies the Vitur client Access Key used for authentication
pub static CS_CLIENT_ACCESS_KEY: &str = "CS_CLIENT_ACCESS_KEY";

/// Specifies the Vitur Workspace the client operates
pub static CS_WORKSPACE_ID: &str = "CS_WORKSPACE_ID";

/// Specifies the path for read/write configs
pub static CS_CONFIG_PATH: &str = "CS_CONFIG_PATH";

/// Specifies whether to enable client-side decryption logging
pub static CS_DECRYPTION_LOG: &str = "CS_DECRYPTION_LOG";
