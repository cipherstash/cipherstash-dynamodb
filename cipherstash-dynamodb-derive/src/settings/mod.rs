mod builder;
pub mod index_type;
use std::collections::HashMap;

use self::{builder::SettingsBuilder, index_type::IndexType};
use itertools::Itertools;
use proc_macro2::Ident;
use syn::{DeriveInput, ExprPath};

pub(crate) enum AttributeMode {
    Protected,
    Plaintext,
    Skipped,
}

pub(crate) struct Settings {
    ident: Ident,
    pub(crate) sort_key_prefix: Option<String>,
    pub(crate) type_name: String,
    pub(crate) sort_key_field: Option<String>,
    pub(crate) partition_key_field: Option<String>,
    protected_attributes: Vec<String>,
    unprotected_attributes: Vec<String>,

    /// Map of attribute names to the encryption handler to use.
    encrypt_handlers: HashMap<String, ExprPath>,

    /// Map of attribute names to the decryption handler to use.
    decrypt_handlers: HashMap<String, ExprPath>,

    /// Skipped attributes are never encrypted by the `DecryptedRecord` trait will
    /// use these to reconstruct the struct via `Default` (like serde).
    skipped_attributes: Vec<String>,
    indexes: Vec<IndexType>,
}

impl Settings {
    pub(crate) fn builder(input: &DeriveInput) -> SettingsBuilder {
        SettingsBuilder::new(input)
    }

    pub(crate) fn ident(&self) -> &Ident {
        &self.ident
    }

    pub(crate) fn protected_attributes(&self) -> Vec<&str> {
        self.protected_attributes
            .iter()
            .map(|s| s.as_str())
            .sorted()
            .collect::<Vec<_>>()
    }

    pub(crate) fn protected_attributes_excluding_handlers(&self) -> Vec<&str> {
        self.protected_attributes
            .iter()
            .filter(|s| !self.encrypt_handlers.contains_key(s.as_str()))
            .filter(|s| !self.decrypt_handlers.contains_key(s.as_str()))
            .map(|s| s.as_str())
            .sorted()
            .collect::<Vec<_>>()
    }

    pub(crate) fn encrypt_handlers(&self) -> &HashMap<String, ExprPath> {
        &self.encrypt_handlers
    }

    pub(crate) fn decrypt_handlers(&self) -> &HashMap<String, ExprPath> {
        &self.decrypt_handlers
    }

    pub(crate) fn plaintext_attributes(&self) -> Vec<&str> {
        self.unprotected_attributes
            .iter()
            .map(|s| s.as_str())
            .sorted()
            .collect::<Vec<_>>()
    }

    pub(crate) fn skipped_attributes(&self) -> Vec<&str> {
        self.skipped_attributes
            .iter()
            .map(|s| s.as_str())
            .sorted()
            .collect::<Vec<_>>()
    }

    /// Return the indexes defined for this struct as a vector sorted by index name.
    /// This is to make downstream functions and tests simpler.
    pub(crate) fn indexes(&self) -> Vec<IndexType> {
        self.indexes
            .iter()
            .sorted_by(|left, right| left.index_name().cmp(&(right.index_name())))
            .cloned()
            .collect()
    }

    pub(crate) fn get_partition_key(&self) -> Option<String> {
        self.partition_key_field.clone()
    }
}
