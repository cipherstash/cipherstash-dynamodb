use super::{
    attrs::{FlattenedProtectedAttributes, NormalizedProtectedAttributes},
    SealError,
};
use crate::{
    encrypted_table::{TableAttribute, TableAttributes},
    Decryptable,
};
use cipherstash_client::encryption::Plaintext;
use std::collections::HashMap;

// FIXME: Remove this (only used for debugging)
#[derive(Debug)]
/// Wrapper to indicate that a value is NOT encrypted
pub struct Unsealed {
    /// Protected plaintexts with their descriptors
    protected: NormalizedProtectedAttributes,
    unprotected: TableAttributes,
}

impl Default for Unsealed {
    fn default() -> Self {
        Self::new()
    }
}

impl Unsealed {
    pub fn new() -> Self {
        Self {
            protected: NormalizedProtectedAttributes::new(),
            unprotected: Default::default(),
        }
    }

    /// Create a new Unsealed with a descriptor prefix.
    pub fn new_with_descriptor(descriptor: impl Into<String>) -> Self {
        Self {
            protected: NormalizedProtectedAttributes::new_with_prefix(descriptor),
            unprotected: Default::default(),
        }
    }

    // TODO: Change this to take_unprotected
    pub fn get_plaintext(&self, name: &str) -> TableAttribute {
        self.unprotected
            .get(name)
            .cloned()
            .unwrap_or(TableAttribute::Null)
    }

    pub fn add_protected(&mut self, name: impl Into<String>, plaintext: impl Into<Plaintext>) {
        self.protected.insert(name, plaintext.into());
    }

    pub fn add_protected_map(&mut self, name: impl Into<String>, map: HashMap<String, Plaintext>) {
        self.protected.insert_map(name, map);
    }

    /// Insert a new key-value pair into a map stored in the protected attributes, `name`.
    /// If the map does not exist, it will be created.
    /// If the map exists, the key-value pair will be updated.
    /// If an attribute called `name` already exists but is not a map, this will panic.
    pub fn add_protected_map_field(&mut self, name: impl Into<String>, subkey: impl Into<String>, value: impl Into<Plaintext>) {
        self.protected.insert_and_update_map(name, subkey, value.into());
    }

    pub fn add_unprotected(&mut self, name: impl Into<String>, attribute: impl Into<TableAttribute>) {
        self.unprotected.insert(name.into(), attribute);
    }

    /// Removes and returns the protected attribute, `name`.
    pub fn take_protected(&mut self, name: &str) -> Option<Plaintext> {
        self.protected.take(name)
    }

    /// Removes and returns the map stored in the protected attributes, `name`.
    /// The caller can convert to whatever type they need.
    pub fn take_protected_map(&mut self, name: &str) -> Option<HashMap<String, Plaintext>> {
        self.protected.take_map(name)
    }

    /// Flatten the protected attributes and returns them along with the unprotected attributes.
    pub(crate) fn flatten_into_parts(self) -> (FlattenedProtectedAttributes, TableAttributes) {
        (self.protected.flatten(), self.unprotected)
    }

    /// Create a new Unsealed from the protected and unprotected attributes.
    pub(crate) fn new_from_parts(
        protected: NormalizedProtectedAttributes,
        unprotected: TableAttributes,
    ) -> Self {
        let mut unsealed = Self::new();
        unsealed.protected = protected;
        unsealed.unprotected = unprotected;
        unsealed
    }

    pub fn into_value<T: Decryptable>(self) -> Result<T, SealError> {
        T::from_unsealed(self)
    }
}

#[cfg(test)]
mod tests {
    /*use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn test_nested_protected() {
        let mut unsealed = Unsealed::new_with_descriptor("test");
        unsealed.add_protected("test.a", Plaintext::from("a"));
        unsealed.add_protected("test.b", Plaintext::from("b"));
        unsealed.add_protected("test.c", Plaintext::from("c"));
        unsealed.add_protected("test.d", Plaintext::from("d"));

        let nested = unsealed
            .nested_protected("test")
            .collect::<BTreeMap<_, _>>();

        assert_eq!(nested.len(), 4);
        assert_eq!(nested["a"], Plaintext::from("a"));
        assert_eq!(nested["b"], Plaintext::from("b"));
        assert_eq!(nested["c"], Plaintext::from("c"));
        assert_eq!(nested["d"], Plaintext::from("d"));
    }

    #[test]
    fn test_flatted_protected_value() {
        let mut map = HashMap::new();
        map.insert("a".to_string(), Plaintext::from("value-a"));
        map.insert("b".to_string(), Plaintext::from("value-b"));
        map.insert("c".to_string(), Plaintext::from("value-c"));
        map.insert("d".to_string(), Plaintext::from("value-d"));

        let protected = NormalizedValue::Map(map, "test".to_string());
        let flattened = protected.flatten();

        assert_eq!(flattened.len(), 4);
        assert!(flattened.contains(&NormalizedValue::Scalar(
            Plaintext::from("value-a"),
            "test.a".to_string()
        )));
        assert!(flattened.contains(&NormalizedValue::Scalar(
            Plaintext::from("value-b"),
            "test.b".to_string()
        )));
        assert!(flattened.contains(&NormalizedValue::Scalar(
            Plaintext::from("value-c"),
            "test.c".to_string()
        )));
        assert!(flattened.contains(&NormalizedValue::Scalar(
            Plaintext::from("value-d"),
            "test.d".to_string()
        )));
    }*/
}
