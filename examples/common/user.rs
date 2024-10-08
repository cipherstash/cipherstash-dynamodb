use cipherstash_dynamodb::{Decryptable, Encryptable, Identifiable, Searchable};

#[derive(Debug, Identifiable, Encryptable, Decryptable, Searchable)]
#[cipherstash(sort_key_prefix = "user")]
pub struct User {
    #[cipherstash(query = "exact", compound = "email#name")]
    #[cipherstash(query = "exact")]
    #[partition_key]
    pub email: String,

    #[cipherstash(query = "prefix", compound = "email#name")]
    #[cipherstash(query = "prefix")]
    pub name: String,

    #[cipherstash(plaintext)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use cipherstash_dynamodb::{IndexType, SingleIndex};
    use std::borrow::Cow;

    #[test]
    fn test_cipherstash_typename() {
        assert_eq!(User::type_name(), "user");
    }

    #[test]
    fn test_cipherstash_attributes() {
        assert_eq!(
            <User as Encryptable>::protected_attributes(),
            vec!["email", "name"]
        );
        assert_eq!(<User as Encryptable>::plaintext_attributes(), vec!["count"]);
    }

    #[test]
    fn test_cipherstash_index_names() {
        assert_eq!(
            User::protected_indexes(),
            vec![
                (
                    Cow::Borrowed("email"),
                    IndexType::Single(SingleIndex::Exact)
                ),
                (
                    Cow::Borrowed("email#name"),
                    IndexType::Compound2((SingleIndex::Exact, SingleIndex::Prefix))
                ),
                (
                    Cow::Borrowed("name"),
                    IndexType::Single(SingleIndex::Prefix)
                ),
            ]
        );
    }
}
