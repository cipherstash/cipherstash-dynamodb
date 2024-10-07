use super::{SealError, TableAttribute};
use std::{borrow::Cow, collections::HashMap};

// FIXME: Remove this (only used for debugging)
#[derive(Debug, Clone)]
/// Represents a collection of attributes for a table entry.
/// Attributes are stored as a map of `String` to `TableAttribute`.
pub struct TableAttributes(HashMap<String, TableAttribute>);

impl TableAttributes {
    pub(crate) fn new() -> Self {
        Self(HashMap::new())
    }

    /// Merge this table attributes with another set of table attributes.
    pub(crate) fn merge(mut self, other: Self) -> Self {
        self.0.extend(other.0);
        self
    }

    // TODO: Test, docs
    // TODO: Remove this logic from the NormalisedKey
    pub(crate) fn insert(&mut self, key: impl Into<String>, value: impl Into<TableAttribute>) {
        let key: String = key.into();
        self.0.insert(to_inner_pksk(key), value.into());
    }

    // TODO: Proper error here
    /// Attempts to insert a value into a map with key `subkey` where the map is stored at `key`.
    /// If the map doesn't exist, it will be created.
    /// If an attribute with the same key already exists but is not a map, an error is returned.
    pub(crate) fn try_insert_map(&mut self, key: impl Into<String>, subkey: impl Into<String>, value: impl Into<TableAttribute>) -> Result<(), SealError> {
        self.0.entry(key.into())
            .or_insert(TableAttribute::new_map())
            .try_insert_map(subkey.into(), value.into())
    }

    // TODO: Add unit tests for this
    /// Partition the attributes into protected and unprotected attributes
    /// given the list of protected keys.
    pub(crate) fn partition(self, protected_keys: &[Cow<'_, str>]) -> (Self, Self) {
        let (protected, unprotected): (HashMap<_, _>, HashMap<_, _>) =
            self.0.into_iter().partition(|(k, _)| {
                let check = from_inner_pksk_ref(k);
                protected_keys.iter().any(|key| match_key(check, key))
            });

        (protected.into(), unprotected.into())
    }

    // TODO: Doc, test
    pub(crate) fn get(&self, key: &str) -> Option<&TableAttribute> {
        self.0.get(to_inner_pksk_ref(key))
    }
}

impl From<HashMap<String, TableAttribute>> for TableAttributes {
    fn from(map: HashMap<String, TableAttribute>) -> Self {
        Self(map)
    }
}

impl IntoIterator for TableAttributes {
    type Item = (String, TableAttribute);
    type IntoIter = std::collections::hash_map::IntoIter<String, TableAttribute>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Default for TableAttributes {
    fn default() -> Self {
        Self::new()
    }
}

// TODO: This may no longer be required - remove and test
// TODO: Make a type for keys that can be namespaced and prefixed
// and implement PartialEq for it - its the same as FlattenedKey
fn match_key(key: &str, other: &Cow<str>) -> bool {
    let namespaced_key = match key.split_once("/") {
        None => key,
        Some((_, key)) => key,
    };
    let key = match namespaced_key.split_once(".") {
        None => namespaced_key,
        Some((key, _)) => key,
    };
    key == other.as_ref()
}

#[inline]
fn to_inner_pksk(key: String) -> String {
    match key.as_str() {
        "pk" => "__pk".into(),
        "sk" => "__sk".into(),
        _ => key,
    }
}

#[inline]
fn to_inner_pksk_ref(key: &str) -> &str {
    match key {
        "pk" => "__pk",
        "sk" => "__sk",
        _ => key,
    }
}

#[inline]
fn from_inner_pksk_ref(key: &str) -> &str {
    match key {
        "__pk" => "pk",
        "__sk" => "sk",
        _ => key,
    }
}