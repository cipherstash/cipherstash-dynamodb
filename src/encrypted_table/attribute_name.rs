/// Represents the name of an attribute for storage in the database.
/// For the most part, this is just a `String`, but it ensures that special columns
/// like `pk` and `sk` are stored in the database as `__pk` and `__sk` respectively.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttributeName(String);

impl AttributeName {
    pub fn new(name: impl Into<String>) -> Self {
        // Always store pk and sk as __pk and __sk
        Self(to_inner_pksk(name.into()))
    }

    /// Returns the name of the attribute as it should be stored in the database.
    /// For example, `pk` will be stored as `__pk`.
    pub fn as_stored_name(&self) -> &str {
        to_inner_pksk_ref(&self.0)
    }

    /// Returns the name of the attribute as it should be stored in the database.
    /// For example, `pk` will be stored as `__pk`.
    pub fn into_stored_name(self) -> String {
        to_inner_pksk(self.0)
    }

    /// Returns the name of the attribute as it should be displayed externally.
    /// For example, `__pk` will be displayed as `pk`.
    pub fn as_external_name(&self) -> &str {
        from_inner_pksk_ref(&self.0)
    }
}

impl From<String> for AttributeName {
    fn from(name: String) -> Self {
        Self::new(name)
    }
}

impl From<&str> for AttributeName {
    fn from(name: &str) -> Self {
        Self::new(name)
    }
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
    fn test_attribute_name() {
        let name = AttributeName::new("pk");
        assert_eq!(name.as_stored_name(), "__pk");
        assert_eq!(name.as_external_name(), "pk");

        let name = AttributeName::new("sk");
        assert_eq!(name.as_stored_name(), "__sk");
        assert_eq!(name.as_external_name(), "sk");

        let name = AttributeName::new("name");
        assert_eq!(name.as_stored_name(), "name");
        assert_eq!(name.as_external_name(), "name");
    }
}
