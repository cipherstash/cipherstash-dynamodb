use super::flattened_protected_attributes::{
    FlattenedAttrName, FlattenedProtectedAttribute, FlattenedProtectedAttributes,
};
use cipherstash_client::encryption::Plaintext;
use std::collections::HashMap;

// FIXME: Remove this (only used for debugging)
#[derive(Debug)]
pub(crate) struct NormalizedProtectedAttributes {
    values: HashMap<NormalizedKey, NormalizedValue>,
    prefix: Option<String>,
}

impl NormalizedProtectedAttributes {
    pub(crate) fn new() -> Self {
        Self {
            values: HashMap::new(),
            prefix: None,
        }
    }

    pub(crate) fn new_with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            values: HashMap::new(),
            prefix: Some(prefix.into()),
        }
    }

    pub fn insert(&mut self, key: impl Into<String>, value: Plaintext) {
        self.values.insert(
            NormalizedKey::Scalar(key.into()),
            NormalizedValue::Scalar(value),
        );
    }

    pub fn insert_map(&mut self, key: impl Into<String>, value: HashMap<String, Plaintext>) {
        self.values
            .insert(NormalizedKey::Map(key.into()), NormalizedValue::Map(value));
    }

    /// Insert a new key-value pair into the map.
    /// If the value doesn't exist, create a new map and insert the key-value pair.
    /// If the value already exists and is a scalar, panic.
    pub fn insert_and_update_map(
        &mut self,
        key: impl Into<String>,
        subkey: impl Into<String>,
        value: Plaintext,
    ) {
        let key = key.into();
        let subkey = subkey.into();

        self.values
            .entry(NormalizedKey::Map(key))
            .or_insert(NormalizedValue::Map(HashMap::new()))
            .insert_map(subkey, value);
    }

    /// Remove and return a protected *scalar* value.
    /// Returns `None` if the key is not found or the value is not a scalar.
    pub fn take(&mut self, name: &str) -> Option<Plaintext> {
        self.values
            .remove(&NormalizedKey::Scalar(name.to_string()))
            .and_then(|v| v.into_scalar())
    }

    /// Remove and return a protected *map* value.
    /// Returns `None` if the key is not found or the value is not a map.
    pub fn take_map(&mut self, name: &str) -> Option<HashMap<String, Plaintext>> {
        self.values
            .remove(&NormalizedKey::Map(name.to_string()))
            .and_then(|v| v.into_map())
    }

    pub(crate) fn flatten(self) -> FlattenedProtectedAttributes {
        let inner: Vec<FlattenedProtectedAttribute> = self
            .values
            .into_iter()
            .flat_map(|(k, v)| v.flatten(k, self.prefix.clone()))
            .collect();

        FlattenedProtectedAttributes(inner)
    }
}

/// Allow a list of key-value pairs to be collected into a [NormalizedProtectedAttributes].
impl FromIterator<(NormalizedKey, NormalizedValue)> for NormalizedProtectedAttributes {
    fn from_iter<T: IntoIterator<Item = (NormalizedKey, NormalizedValue)>>(iter: T) -> Self {
        let values = iter.into_iter().collect();
        Self {
            values,
            prefix: None,
        }
    }
}

impl FromIterator<FlattenedProtectedAttribute> for NormalizedProtectedAttributes {
    fn from_iter<T: IntoIterator<Item = FlattenedProtectedAttribute>>(iter: T) -> Self {
        iter.into_iter().fold(Self::new(), |mut acc, fpa| {
            match fpa.normalize_into_parts() {
                (plaintext, key, Some(subkey)) => {
                    acc.insert_and_update_map(key, subkey, plaintext);
                }
                (plaintext, key, None) => {
                    acc.insert(key, plaintext);
                }
            }
            acc
        })
    }
}

/// Normalized keys are effectively just strings but wrapping them in an enum allows us to
/// differentiate between scalar and map keys without checking the value.
#[derive(PartialEq, Debug, Hash, Eq)]
pub(crate) enum NormalizedKey {
    Scalar(String),
    Map(String),
}

impl NormalizedKey {
    pub(super) fn new_scalar(key: impl Into<String>) -> Self {
        Self::Scalar(key.into())
    }

    pub(super) fn new_map(key: impl Into<String>) -> Self {
        Self::Map(key.into())
    }

    /// Converts the key into a [FlattenedKey].
    fn flatten(self, prefix: Option<String>) -> FlattenedAttrName {
        let key: String = String::from(self);
        FlattenedAttrName::new(prefix, key)
    }
}

impl From<NormalizedKey> for String {
    fn from(key: NormalizedKey) -> Self {
        match key {
            NormalizedKey::Scalar(s) | NormalizedKey::Map(s) => s,
        }
    }
}

// TODO: Don't debug or only derive in tests
#[derive(PartialEq, Debug)]
pub(crate) enum NormalizedValue {
    Scalar(Plaintext),
    Map(HashMap<String, Plaintext>),
}

impl NormalizedValue {
    /// Flatten the value into a list of [FlattenedProtectedAttribute]s.
    fn flatten(
        self,
        key: NormalizedKey,
        prefix: Option<String>,
    ) -> Vec<FlattenedProtectedAttribute> {
        let key = key.flatten(prefix);

        match self {
            Self::Scalar(plaintext) => vec![FlattenedProtectedAttribute::new(plaintext, key)],
            Self::Map(map) => map
                .into_iter()
                .map(|(subkey, plaintext)| {
                    FlattenedProtectedAttribute::new(plaintext, key.clone().with_subkey(subkey))
                })
                .collect(),
        }
    }

    /// Insert a new key-value pair into the map.
    /// If the value is not a map, panic.
    fn insert_map(&mut self, key: String, value: Plaintext) {
        match self {
            Self::Map(map) => {
                map.insert(key, value);
            }
            _ => panic!("Cannot insert into a scalar value"),
        }
    }

    /// Return the invariant value as a scalar if it is one.
    fn into_scalar(self) -> Option<Plaintext> {
        match self {
            Self::Scalar(plaintext) => Some(plaintext),
            _ => None,
        }
    }

    /// Return the invariant value as a map if it is one.
    fn into_map(self) -> Option<HashMap<String, Plaintext>> {
        match self {
            Self::Map(map) => Some(map),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalized_key() {
        let scalar = NormalizedKey::Scalar("scalar".to_string());
        let map = NormalizedKey::Map("map".to_string());

        assert_eq!(String::from(scalar), "scalar");
        assert_eq!(String::from(map), "map");
    }

    #[test]
    fn test_normalized_key_partial_eq() {
        assert_eq!(
            NormalizedKey::Scalar("a".to_string()),
            NormalizedKey::Scalar("a".to_string())
        );
        assert_ne!(
            NormalizedKey::Scalar("a".to_string()),
            NormalizedKey::Scalar("b".to_string())
        );
        assert_eq!(
            NormalizedKey::Map("a".to_string()),
            NormalizedKey::Map("a".to_string())
        );
        assert_ne!(
            NormalizedKey::Map("a".to_string()),
            NormalizedKey::Map("b".to_string())
        );
        assert_ne!(
            NormalizedKey::Scalar("a".to_string()),
            NormalizedKey::Map("a".to_string())
        );
    }

    #[test]
    fn test_normalized_value_into_scalar() {
        let scalar = NormalizedValue::Scalar(Plaintext::from("scalar"));
        let map = NormalizedValue::Map(HashMap::new());

        assert_eq!(scalar.into_scalar(), Some(Plaintext::from("scalar")));
        assert_eq!(map.into_scalar(), None);
    }

    #[test]
    fn test_normalized_value_into_map() {
        let scalar = NormalizedValue::Scalar(Plaintext::from("scalar"));
        let mut map_inner = HashMap::new();
        map_inner.insert("a".to_string(), Plaintext::from("a"));
        let map = NormalizedValue::Map(map_inner.clone());

        assert_eq!(scalar.into_map(), None);
        assert_eq!(map.into_map(), Some(map_inner));
    }

    #[test]
    fn test_flatten_scalar_no_prefix() {
        let key = NormalizedValue::Scalar(Plaintext::from("value"));
        let flattened = key.flatten(NormalizedKey::Scalar("key".to_string()), None);
        assert_eq!(
            flattened,
            vec![FlattenedProtectedAttribute::new(
                Plaintext::from("value"),
                FlattenedAttrName::new(None, "key".to_string())
            )]
        );
    }

    #[test]
    fn test_flatten_scalar_with_prefix() {
        let key = NormalizedValue::Scalar(Plaintext::from("value"));
        let flattened = key.flatten(
            NormalizedKey::Scalar("key".to_string()),
            Some("prefix".to_string()),
        );
        assert_eq!(
            flattened,
            vec![FlattenedProtectedAttribute::new(
                Plaintext::from("value"),
                FlattenedAttrName::new(Some("prefix".to_string()), "key".to_string())
            )]
        );
    }

    #[test]
    fn test_flatten_map_no_prefix() {
        let mut map = HashMap::new();
        map.insert("a".to_string(), Plaintext::from("value-a"));
        map.insert("b".to_string(), Plaintext::from("value-b"));
        let key = NormalizedValue::Map(map.clone());

        let flattened = key.flatten(NormalizedKey::Map("key".to_string()), None);
        assert!(flattened.contains(&FlattenedProtectedAttribute::new(
            Plaintext::from("value-a"),
            FlattenedAttrName::new(None, "key".to_string()).with_subkey("a".to_string())
        )));
        assert!(flattened.contains(&FlattenedProtectedAttribute::new(
            Plaintext::from("value-b"),
            FlattenedAttrName::new(None, "key".to_string()).with_subkey("b".to_string())
        )));
    }

    #[test]
    fn test_flatten_map_with_prefix() {
        let mut map = HashMap::new();
        map.insert("a".to_string(), Plaintext::from("value-a"));
        map.insert("b".to_string(), Plaintext::from("value-b"));
        let key = NormalizedValue::Map(map.clone());

        let flattened = key.flatten(
            NormalizedKey::Map("key".to_string()),
            Some("prefix".to_string()),
        );
        assert!(flattened.contains(&FlattenedProtectedAttribute::new(
            Plaintext::from("value-a"),
            FlattenedAttrName::new(Some("prefix".to_string()), "key".to_string())
                .with_subkey("a".to_string())
        )));
        assert!(flattened.contains(&FlattenedProtectedAttribute::new(
            Plaintext::from("value-b"),
            FlattenedAttrName::new(Some("prefix".to_string()), "key".to_string())
                .with_subkey("b".to_string())
        )));
    }
}
