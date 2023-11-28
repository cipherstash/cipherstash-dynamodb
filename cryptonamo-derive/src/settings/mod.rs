mod builder;
pub mod index_type;
use self::{builder::SettingsBuilder, index_type::IndexType};
use indexmap::IndexMap;
use itertools::Itertools;
use proc_macro2::Ident;
use std::collections::HashMap;
use syn::DeriveInput;

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

    /// Skipped attributes are never encrypted by the `DecryptedRecord` trait will
    /// use these to reconstruct the struct via `Default` (like serde).
    skipped_attributes: Vec<String>,
    indexes: HashMap<String, IndexType>,
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

    /// Return the indexes defined for this struct as an `IndexMap` sorted by index name.
    /// This is to make downstream functions and tests simpler.
    pub(crate) fn indexes(&self) -> IndexMap<&str, IndexType> {
        self.indexes
            .iter()
            .sorted_by(|(k1, _), (k2, _)| k1.cmp(k2))
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect()
    }

    pub(crate) fn get_partition_key(&self) -> Result<String, syn::Error> {
        self.partition_key_field.clone().ok_or_else(|| {
            syn::Error::new_spanned(
                &self.sort_key_prefix,
                "No partition key defined for this struct",
            )
        })
    }
}
