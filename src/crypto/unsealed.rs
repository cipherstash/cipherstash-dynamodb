use super::{
    attrs::{FlattenedProtectedAttributes, NormalizedProtectedAttributes},
    SealError,
};
use crate::{
    encrypted_table::{AttributeName, TableAttribute, TableAttributes},
    Decryptable,
};
use cipherstash_client::encryption::Plaintext;
use std::collections::HashMap;

/// Wrapper to which values are added prior to being encrypted.
/// Values added as "protected" (e.g. via [Unsealed::add_protected]) will be encrypted.
/// Values added as "unprotected" (e.g. via [Unsealed::add_unprotected]) will not be encrypted.
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

    #[deprecated(since = "0.7.3", note = "Use `Unsealed::take_unprotected` instead")]
    pub fn get_plaintext(&self, name: impl Into<AttributeName>) -> TableAttribute {
        self.unprotected
            .get(name)
            .cloned()
            .unwrap_or(TableAttribute::Null)
    }

    /// Add a new protected attribute, `name`, with the given plaintext.
    pub fn add_protected(&mut self, name: impl Into<String>, plaintext: impl Into<Plaintext>) {
        self.protected.insert(name, plaintext.into());
    }

    /// Add a new protected map, `name`, with the given map of plaintexts.
    pub fn add_protected_map(&mut self, name: impl Into<String>, map: HashMap<String, Plaintext>) {
        self.protected.insert_map(name, map);
    }

    /// Insert a new key-value pair into a map stored in the protected attributes, `name`.
    /// If the map does not exist, it will be created.
    /// If the map exists, the key-value pair will be updated.
    /// If an attribute called `name` already exists but is not a map, this will panic.
    pub fn add_protected_map_field(
        &mut self,
        name: impl Into<String>,
        subkey: impl Into<String>,
        value: impl Into<Plaintext>,
    ) {
        self.protected
            .insert_and_update_map(name, subkey, value.into());
    }

    /// Add a new unprotected attribute, `name`, with the given plaintext.
    pub fn add_unprotected(
        &mut self,
        name: impl Into<AttributeName>,
        attribute: impl Into<TableAttribute>,
    ) {
        self.unprotected.insert(name, attribute);
    }

    /// Removes and returns the unprotected attribute, `name`.
    /// See also [TableAttribute].
    ///
    /// If the attribute does not exist, `TableAttribute::Null` is returned.
    pub fn take_unprotected(&mut self, name: impl Into<AttributeName>) -> TableAttribute {
        self.unprotected
            .remove(name)
            .unwrap_or(TableAttribute::Null)
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

    /// Convert `self` into `T` using the attributes stored in `self`.
    /// The [Decryptable] trait must be implemented for `T` and this method calls [Decryptable::from_unsealed].
    pub fn into_value<T: Decryptable>(self) -> Result<T, SealError> {
        T::from_unsealed(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_protected_field() {
        let mut unsealed = Unsealed::new_with_descriptor("test");
        unsealed.add_protected("test", "value");

        let plaintext = unsealed.take_protected("test").unwrap();
        assert_eq!(plaintext, Plaintext::from("value"));
    }

    #[test]
    fn test_protected_map() {
        let mut unsealed = Unsealed::new_with_descriptor("test");
        let mut map = HashMap::new();
        map.insert("a".to_string(), Plaintext::from("value-a"));
        map.insert("b".to_string(), Plaintext::from("value-b"));
        map.insert("c".to_string(), Plaintext::from("value-c"));
        unsealed.add_protected_map("test", map);

        let nested: BTreeMap<String, Plaintext> = unsealed
            .take_protected_map("test")
            .unwrap()
            .into_iter()
            .collect();

        assert_eq!(nested.len(), 3);
        assert_eq!(nested["a"], Plaintext::from("value-a"));
        assert_eq!(nested["b"], Plaintext::from("value-b"));
        assert_eq!(nested["c"], Plaintext::from("value-c"));
    }

    #[test]
    fn test_protected_map_field() {
        let mut unsealed = Unsealed::new_with_descriptor("test");
        unsealed.add_protected_map_field("test", "a", "value-a");
        unsealed.add_protected_map_field("test", "b", "value-b");
        unsealed.add_protected_map_field("test", "c", "value-c");

        let nested: BTreeMap<String, Plaintext> = unsealed
            .take_protected_map("test")
            .unwrap()
            .into_iter()
            .collect();

        assert_eq!(nested.len(), 3);
        assert_eq!(nested["a"], Plaintext::from("value-a"));
        assert_eq!(nested["b"], Plaintext::from("value-b"));
        assert_eq!(nested["c"], Plaintext::from("value-c"));
    }

    #[test]
    fn test_protected_mixed() {
        let mut unsealed = Unsealed::new_with_descriptor("test");
        unsealed.add_protected("test", "value");
        unsealed.add_protected_map_field("attrs", "a", "value-a");
        unsealed.add_protected_map_field("attrs", "b", "value-b");
        unsealed.add_protected_map_field("attrs", "c", "value-c");

        let plaintext = unsealed.take_protected("test").unwrap();
        assert_eq!(plaintext, Plaintext::from("value"));

        let nested: BTreeMap<String, Plaintext> = unsealed
            .take_protected_map("attrs")
            .unwrap()
            .into_iter()
            .collect();

        assert_eq!(nested.len(), 3);
        assert_eq!(nested["a"], Plaintext::from("value-a"));
        assert_eq!(nested["b"], Plaintext::from("value-b"));
        assert_eq!(nested["c"], Plaintext::from("value-c"));
    }

    #[test]
    #[should_panic]
    fn test_protected_map_override() {
        let mut unsealed = Unsealed::new_with_descriptor("test");
        unsealed.add_protected("test", "value");
        // Panics because "test" is already a protected scalar
        unsealed.add_protected_map_field("test", "a", "value-a");
    }

    #[test]
    fn test_unprotected() {
        let mut unsealed = Unsealed::new_with_descriptor("test");
        unsealed.add_unprotected("test", "value");

        let attribute = unsealed.take_unprotected("test");
        assert!(attribute == "value".into(), "values do not match");
    }
}
