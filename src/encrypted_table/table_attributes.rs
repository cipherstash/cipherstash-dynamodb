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

    // TODO: Is it possible that we should only normalize protected attributes?
    // To deal with that, we could use a TypeState pattern and have a separate type for protected and unprotected attributes.

    /// Normalize the attributes by splitting namespaced attributes into their own maps.
    ///
    /// For example:
    ///
    /// ```ignore
    /// "attr.a" => "value-a"
    /// // Becomes
    /// "attr" => { "a" => "value-a" }
    /// ```
    ///
    pub(crate) fn normalize(self) -> Self {
        self.0
            .into_iter()
            .fold(HashMap::new(), |mut acc, (key, value)| {
                // TODO: Split the key on the first period and use the first part as the namespace
                // and the second part as the key
                if let Some((namespace, key)) = key.split_once('.') {
                    // TODO: Can we avoid the clone here?
                    // TODO: Don't unwrap here
                    acc.entry(namespace.to_string())
                        .or_insert(TableAttribute::new_map())
                        .try_insert_map(key.to_string(), value)
                        .unwrap();
                } else {
                    acc.insert(key, value);
                }
                acc
            })
            .into()
    }

    pub(crate) fn denormalize(self) -> Self {
        self.0
            .into_iter()
            .fold(HashMap::new(), |mut acc, (namespace, value)| {
                if let TableAttribute::Map(map) = value {
                    for (key, value) in map {
                        acc.insert(format!("{}.{}", namespace, key), value);
                    }
                } else {
                    acc.insert(namespace, value);
                }
                acc
            })
            .into()
    }

    // TODO: Add unit tests for this
    /// Partition the attributes into protected and unprotected attributes
    /// given the list of protected keys.
    pub(crate) fn partition(self, protected_keys: &[Cow<'_, str>]) -> (Self, Self) {
        println!("Protected keys: {:?}", protected_keys);
        let (protected, unprotected): (HashMap<_, _>, HashMap<_, _>) =
            self.0.into_iter().partition(|(k, _)| {
                let check = from_inner_pksk_ref(k);
                println!("Checking if {} is in protected_keys", check);
                let r = protected_keys.iter().any(|key| match_key(check, key));
                println!("Result: {}", r);
                r
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_no_namespaced_values() {
        let mut table_attributes = TableAttributes::new();
        table_attributes.insert("a", "value-a");
        table_attributes.insert("b", "value-b");
        table_attributes.insert("c", "value-c");

        let normalized = table_attributes.normalize();

        assert_eq!(normalized.0.len(), 3);
        assert_eq!(
            normalized.get("a").unwrap(),
            &TableAttribute::from("value-a")
        );
        assert_eq!(
            normalized.get("b").unwrap(),
            &TableAttribute::from("value-b")
        );
        assert_eq!(
            normalized.get("c").unwrap(),
            &TableAttribute::from("value-c")
        );
    }

    #[test]
    fn normalize_one_namespaced_value() {
        let mut table_attributes = TableAttributes::new();
        table_attributes.insert("attr.a", "value-a");
        table_attributes.insert("b", "value-b");
        table_attributes.insert("c", "value-c");

        let normalized = table_attributes.normalize();

        assert_eq!(normalized.0.len(), 3);
        let mut check = TableAttribute::new_map();
        check.try_insert_map("a", "value-a").unwrap();
        assert_eq!(normalized.get("attr").unwrap(), &check);
        assert_eq!(
            normalized.get("b").unwrap(),
            &TableAttribute::from("value-b")
        );
        assert_eq!(
            normalized.get("c").unwrap(),
            &TableAttribute::from("value-c")
        );
    }

    #[test]
    fn normalize_multiple_namespaced_values() {
        let mut table_attributes = TableAttributes::new();
        table_attributes.insert("attr.a", "value-a");
        table_attributes.insert("attr.b", "value-b");
        table_attributes.insert("attr.c", "value-c");
        table_attributes.insert("other", "value-other");

        let normalized = table_attributes.normalize();

        assert_eq!(normalized.0.len(), 2);
        let mut check = TableAttribute::new_map();
        check.try_insert_map("a", "value-a").unwrap();
        check.try_insert_map("b", "value-b").unwrap();
        check.try_insert_map("c", "value-c").unwrap();

        assert_eq!(normalized.get("attr").unwrap(), &check);
        assert_eq!(
            normalized.get("other").unwrap(),
            &TableAttribute::from("value-other")
        );
    }

    #[test]
    fn denormalize_no_namespaced_values() {
        let mut table_attributes = TableAttributes::new();
        table_attributes.insert("a", "value-a");
        table_attributes.insert("b", "value-b");
        table_attributes.insert("c", "value-c");

        let normalized = table_attributes.denormalize();

        assert_eq!(normalized.0.len(), 3);
        assert_eq!(
            normalized.get("a").unwrap(),
            &TableAttribute::from("value-a")
        );
        assert_eq!(
            normalized.get("b").unwrap(),
            &TableAttribute::from("value-b")
        );
        assert_eq!(
            normalized.get("c").unwrap(),
            &TableAttribute::from("value-c")
        );
    }

    #[test]
    fn denormalize_one_namespaced_values() {
        let mut table_attributes = TableAttributes::new();
        let mut map = TableAttribute::new_map();
        map.try_insert_map("a", "value-a").unwrap();
        table_attributes.insert("attrs", map);
        table_attributes.insert("b", "value-b");
        table_attributes.insert("c", "value-c");

        let normalized = table_attributes.denormalize();

        assert_eq!(normalized.0.len(), 3);
        assert_eq!(
            normalized.get("attrs.a").unwrap(),
            &TableAttribute::from("value-a")
        );
        assert_eq!(
            normalized.get("b").unwrap(),
            &TableAttribute::from("value-b")
        );
        assert_eq!(
            normalized.get("c").unwrap(),
            &TableAttribute::from("value-c")
        );
    }

    #[test]
    fn denormalize_multiple_namespaced_values() {
        let mut table_attributes = TableAttributes::new();
        let mut map = TableAttribute::new_map();
        map.try_insert_map("a", "value-a").unwrap();
        map.try_insert_map("b", "value-b").unwrap();
        map.try_insert_map("c", "value-c").unwrap();

        table_attributes.insert("attrs", map);
        table_attributes.insert("o", "value-o");

        let normalized = table_attributes.denormalize();

        assert_eq!(normalized.0.len(), 4);
        assert_eq!(
            normalized.get("attrs.a").unwrap(),
            &TableAttribute::from("value-a")
        );
        assert_eq!(
            normalized.get("attrs.b").unwrap(),
            &TableAttribute::from("value-b")
        );
        assert_eq!(
            normalized.get("attrs.c").unwrap(),
            &TableAttribute::from("value-c")
        );
        assert_eq!(
            normalized.get("o").unwrap(),
            &TableAttribute::from("value-o")
        );
    }

    // TODO: Test for malformed namespaced values
    // TODO: Test partially normalized and denormalised values
}
