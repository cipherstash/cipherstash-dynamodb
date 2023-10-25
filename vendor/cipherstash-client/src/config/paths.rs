//! Internal module for config-related path handling.

use super::errors;
use super::vars::CS_CONFIG_PATH;

use std::env;
use std::path::{Path, PathBuf};

const DEFAULT_CS_CONFIG_DIR_NAME: &str = ".cipherstash";

pub(crate) fn default_config_path() -> Result<PathBuf, errors::ConfigError> {
    if let Some(home_dir) = dirs::home_dir() {
        Ok(home_dir.join(DEFAULT_CS_CONFIG_DIR_NAME))
    } else {
        Err(errors::ConfigError::HomeDirError(
            "Unable to resolve home directory for default CS config path".to_string(),
        ))
    }
}

pub(crate) fn resolve_config_dir(
    config_path: Option<PathBuf>,
) -> Result<PathBuf, errors::ConfigError> {
    if let Some(path) = config_path {
        Ok(path)
    } else if let Ok(path) = env::var(CS_CONFIG_PATH) {
        Ok(Path::new(&path).to_owned())
    } else {
        default_config_path()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "windows"))]
    use super::*;

    #[cfg(not(target_os = "windows"))]
    use std::path::Path;

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_default_dir_is_home_slash_dot_cipherstash_on_non_windows() {
        let default_config_path = default_config_path().unwrap();
        let expected_config_path = Path::new(std::env!("HOME")).join(".cipherstash");
        assert_eq!(default_config_path, expected_config_path)
    }
}
