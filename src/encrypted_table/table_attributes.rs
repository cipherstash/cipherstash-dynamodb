use super::{AttributeName, SealError, TableAttribute};
use std::{
    borrow::Cow,
    collections::{hash_map::IntoIter, HashMap},
};

// FIXME: Remove this (only used for debugging)
#[derive(Debug, Clone)]
/// Represents a collection of attributes for a table entry.
/// Attributes are stored as a map of `String` to `TableAttribute`.
pub struct TableAttributes(HashMap<AttributeName, TableAttribute>);

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
    pub(crate) fn insert(
        &mut self,
        name: impl Into<AttributeName>,
        value: impl Into<TableAttribute>,
    ) {
        let name: AttributeName = name.into();
        self.0.insert(name, value.into());
    }

    /// Attempts to insert a value into a map with key `subkey` where the map is stored at `key`.
    /// If the map doesn't exist, it will be created.
    /// If an attribute with the same key already exists but is not a map, an error is returned.
    pub(crate) fn try_insert_map(
        &mut self,
        name: impl Into<AttributeName>,
        subkey: impl Into<String>,
        value: impl Into<TableAttribute>,
    ) -> Result<(), SealError> {
        self.0
            .entry(name.into())
            .or_insert(TableAttribute::new_map())
            .try_insert_map(subkey.into(), value.into())
    }

    // TODO: Add unit tests for this
    /// Partition the attributes into protected and unprotected attributes
    /// given the list of protected keys.
    pub(crate) fn partition(self, protected_keys: &[Cow<'_, str>]) -> (Self, Self) {
        let (protected, unprotected): (HashMap<_, _>, HashMap<_, _>) =
            self.0.into_iter().partition(|(k, _)| {
                let check = k.as_external_name();
                //protected_keys.iter().any(|key| match_key(check, key))
                protected_keys.iter().any(|key| check == key)
            });

        (protected.into(), unprotected.into())
    }

    // TODO: Doc, test
    pub(crate) fn get(&self, name: impl Into<AttributeName>) -> Option<&TableAttribute> {
        let name: AttributeName = name.into();
        self.0.get(&name)
    }
}

impl From<HashMap<AttributeName, TableAttribute>> for TableAttributes {
    fn from(map: HashMap<AttributeName, TableAttribute>) -> Self {
        Self(map)
    }
}

impl IntoIterator for TableAttributes {
    type Item = (AttributeName, TableAttribute);
    type IntoIter = IntoIter<AttributeName, TableAttribute>;

    /// Iterates over the table attributes, returning each pair of [AttributeName] and [TableAttribute].
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Default for TableAttributes {
    fn default() -> Self {
        Self::new()
    }
}
