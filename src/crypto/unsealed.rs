use crate::{encrypted_table::TableAttribute, Decryptable};
use cipherstash_client::encryption::Plaintext;
use std::collections::HashMap;

use super::SealError;

// TODO: Zeroize, Debug, Display overrides (from SafeVec?)
/// Wrapper to indicate that a value is NOT encrypted
pub struct Unsealed {
    /// Optional descriptor prefix
    descriptor: Option<String>,

    /// Protected plaintexts with their descriptors
    protected: HashMap<String, (Plaintext, String)>,
    unprotected: HashMap<String, TableAttribute>,
}

impl Unsealed {
    pub(super) fn new() -> Self {
        Self {
            descriptor: None,
            protected: Default::default(),
            unprotected: Default::default(),
        }
    }

    pub(super) fn new_with_descriptor(descriptor: impl Into<String>) -> Self {
        Self {
            descriptor: Some(descriptor.into()),
            protected: Default::default(),
            unprotected: Default::default(),
        }
    }

    // TODO: Rename these to get_protected and get_unprotected
    pub fn from_protected(&self, name: &str) -> Result<&Plaintext, SealError> {
        let (plaintext, _) = self
            .protected
            .get(name)
            .ok_or(SealError::MissingAttribute(name.to_string()))?;

        Ok(plaintext)
    }

    pub fn from_plaintext(&self, name: &str) -> Result<TableAttribute, SealError> {
        Ok(self
            .unprotected
            .get(name)
            .ok_or(SealError::MissingAttribute(name.to_string()))?
            .clone())
    }

    pub(super) fn add_protected(&mut self, name: impl Into<String>, plaintext: Plaintext) {
        let name = name.into();
        let descriptor = format!("{}{}", self.descriptor.as_deref().unwrap_or(""), &name);
        self.protected.insert(name, (plaintext, descriptor));
    }

    pub(super) fn add_unprotected(&mut self, name: impl Into<String>, attribute: TableAttribute) {
        self.unprotected.insert(name.into(), attribute);
    }

    pub(crate) fn unprotected(&self) -> HashMap<String, TableAttribute> {
        self.unprotected.clone()
    }

    /// Returns a reference to the protected value along with its descriptor.
    pub(crate) fn protected_with_descriptor(
        &self,
        name: &str,
    ) -> Result<(&Plaintext, &str), SealError> {
        let out = self
            .protected
            .get(name)
            .ok_or(SealError::MissingAttribute(name.to_string()))?;
        Ok((&out.0, &out.1))
    }

    pub(super) fn into_value<T>(self) -> Result<T, SealError>
    where
        T: Decryptable,
    {
        T::from_unsealed(self)
    }
}
