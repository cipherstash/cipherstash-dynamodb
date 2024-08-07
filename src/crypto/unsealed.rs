use crate::{encrypted_table::TableAttribute, Decryptable};
use cipherstash_client::encryption::Plaintext;
use std::collections::HashMap;

use super::SealError;

/// Wrapper to indicate that a value is NOT encrypted
pub struct Unsealed {
    /// Optional descriptor prefix
    descriptor: Option<String>,

    /// Protected plaintexts with their descriptors
    protected: HashMap<String, (Plaintext, String)>,
    unprotected: HashMap<String, TableAttribute>,
}

impl Unsealed {
    pub fn new() -> Self {
        Self {
            descriptor: None,
            protected: Default::default(),
            unprotected: Default::default(),
        }
    }

    pub fn new_with_descriptor(descriptor: impl Into<String>) -> Self {
        Self {
            descriptor: Some(descriptor.into()),
            protected: Default::default(),
            unprotected: Default::default(),
        }
    }

    pub fn get_protected(&self, name: &str) -> Result<&Plaintext, SealError> {
        let (plaintext, _) = self
            .protected
            .get(name)
            .ok_or_else(|| SealError::MissingAttribute(name.to_string()))?;

        Ok(plaintext)
    }

    pub fn get_plaintext(&self, name: &str) -> Result<TableAttribute, SealError> {
        self.unprotected
            .get(name)
            .cloned()
            .ok_or_else(|| SealError::MissingAttribute(name.to_string()))
    }

    pub fn add_protected(&mut self, name: impl Into<String>, plaintext: Plaintext) {
        let name = name.into();
        let descriptor = format!("{}/{}", self.descriptor.as_deref().unwrap_or(""), &name);
        self.protected.insert(name, (plaintext, descriptor));
    }

    pub fn add_unprotected(&mut self, name: impl Into<String>, attribute: TableAttribute) {
        self.unprotected.insert(name.into(), attribute);
    }

    pub(crate) fn unprotected(&self) -> HashMap<String, TableAttribute> {
        self.unprotected.clone()
    }

    /// Remove and return a protected value along with its descriptor.
    pub(crate) fn remove_protected_with_descriptor(
        &mut self,
        name: &str,
    ) -> Result<(Plaintext, String), SealError> {
        let out = self
            .protected
            .remove(name)
            .ok_or(SealError::MissingAttribute(name.to_string()))?;

        Ok(out)
    }

    pub fn into_value<T: Decryptable>(self) -> Result<T, SealError> {
        T::from_unsealed(self)
    }
}
