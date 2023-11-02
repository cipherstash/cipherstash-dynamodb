use cryptonamo::{Cryptonamo, DecryptedRecord, EncryptedRecord, SearchableRecord};

#[derive(Debug, Cryptonamo)]
#[cryptonamo(partition_key = "email")]
#[cryptonamo(sort_key_prefix = "user")]
pub struct User {
    #[cryptonamo(query = "exact", compound = "email#name")]
    #[cryptonamo(query = "exact")]
    pub email: String,

    #[cryptonamo(query = "prefix", compound = "email#name")]
    #[cryptonamo(query = "prefix")]
    pub name: String,

    #[cryptonamo(plaintext)]
    pub count: i32,
}

impl User {
    #[allow(dead_code)]
    pub fn new(email: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            name: name.into(),
            count: 100,
        }
    }
}

// TODO: Move all these into a proper tests module
#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use super::*;

    #[test]
    fn test_cryptonamo_typename() {
        assert_eq!(User::type_name(), "user");
    }

    #[test]
    fn test_cryptonamo_instance() {
        let user = User::new("person@example.net", "Person Name");
        assert_eq!(user.partition_key(), "person@example.net");
    }

    #[test]
    fn test_cryptonamo_attributes() {
        assert_eq!(User::protected_attributes(), vec!["email", "name"]);
        assert_eq!(User::plaintext_attributes(), vec!["count"]);
    }

    #[test]
    fn test_cryptonamo_index_names() {
        assert_eq!(
            User::protected_indexes(),
            vec!["email", "email#name", "name"]
        );
    }
}
