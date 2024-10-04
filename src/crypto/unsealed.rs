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

impl Default for Unsealed {
    fn default() -> Self {
        Self::new()
    }
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

    pub fn protected(&self) -> &HashMap<String, (Plaintext, String)> {
        &self.protected
    }

    pub fn unprotected(&self) -> &HashMap<String, TableAttribute> {
        &self.unprotected
    }

    pub fn get_protected(&self, name: &str) -> Option<&Plaintext> {
        let (plaintext, _) = self.protected.get(name)?;

        Some(plaintext)
    }

    pub fn get_plaintext(&self, name: &str) -> TableAttribute {
        self.unprotected
            .get(name)
            .cloned()
            .unwrap_or(TableAttribute::Null)
    }

    pub fn add_protected(&mut self, name: impl Into<String>, plaintext: Plaintext) {
        let name = name.into();
        let descriptor = format!("{}/{}", self.descriptor.as_deref().unwrap_or(""), &name);
        self.protected.insert(name, (plaintext, descriptor));
    }

    pub fn add_unprotected(&mut self, name: impl Into<String>, attribute: TableAttribute) {
        self.unprotected.insert(name.into(), attribute);
    }

    // TODO: Add docs
    // TODO: Repeat for unprotected
    pub fn nested_protected<'p>(&'p self, prefix: &'p str) -> impl Iterator<Item = (String, Plaintext)> + 'p {
        // TODO: Make adding the . idempotent
        let prefix = format!("{}.", prefix);
        self.protected
            .iter()
            .filter_map(move |(k, v)| {
                // TODO: Remove the prefix from the key
                // TODO: This function should consume
                k.strip_prefix(&prefix).map(|k| (k.to_string(), v.0.clone()))
            })
            //.collect()
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

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
}
