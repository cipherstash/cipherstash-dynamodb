use super::TokenExpiry;
use miette::Diagnostic;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Diagnostic, Error, Debug)]
pub enum SetTokenError {
    #[error("IOWriteError: {0}")]
    IOWriteError(#[from] std::io::Error),

    #[error("JsonError: {0}")]
    JsonError(#[from] serde_json::Error),
}

#[derive(Error, Debug)]
pub enum ClearTokenError {
    #[error("IOWriteError: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug)]
pub struct TokenStore<Token: for<'a> TokenExpiry<'a>> {
    token_path: PathBuf,
    cached_token: Option<Token>,
}

impl<Token: for<'a> TokenExpiry<'a>> TokenStore<Token> {
    pub fn new(token_path: &Path) -> Self {
        let cached_token: Option<Token> = std::fs::read_to_string(token_path)
            .ok()
            .and_then(|x| serde_json::from_str(&x).ok());

        let token_path = token_path.to_owned();

        Self {
            token_path,
            cached_token,
        }
    }

    pub fn get(&mut self) -> Option<Token> {
        // reads token from in-memory cache
        if let Some(token) = &self.cached_token {
            if !token.is_expired() {
                return Some(token.clone());
            }
        }

        // reads token from disk, as it might have been updated outside the scope of this struct
        let token_from_disk: Option<Token> = std::fs::read_to_string(&self.token_path)
            .ok()
            .and_then(|x| serde_json::from_str(&x).ok());

        if let Some(token) = &token_from_disk {
            self.cached_token = Some(token.clone());
            return Some(token.clone());
        }

        None
    }

    pub fn set(&mut self, token: &Token) -> Result<(), SetTokenError> {
        // Replaces the in-memory cache
        self.cached_token = Some(token.clone());

        // Saves the token to disk
        let json_string = serde_json::to_string_pretty(token)?;
        std::fs::write(&self.token_path, json_string)?;

        Ok(())
    }

    pub fn clear(&mut self) -> Result<(), ClearTokenError> {
        self.cached_token = None;

        if self.token_path.exists() {
            std::fs::remove_file(&self.token_path)?;
        }

        Ok(())
    }
}
