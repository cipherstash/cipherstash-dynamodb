use cryptonamo::{traits::DecryptedRecord, Plaintext};
use cryptonamo_derive::Cryptonamo;
use std::collections::HashMap;

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

/*impl SearchableRecord for User {
    fn protected_indexes() -> Vec<&'static str> {
        vec!["name", "email#name"]
    }

    fn index_by_name(name: &str) -> Option<Box<dyn ComposableIndex>> {
        match name {
            "name" => Some(Box::new(PrefixIndex::new("name", vec![], 3, 10))),
            "email#name" => Some(Box::new(
                CompoundIndex::new(ExactIndex::new("email", vec![])).and(PrefixIndex::new(
                    "name",
                    vec![],
                    3,
                    10,
                )),
            )),
            _ => None,
        }
    }

    fn attribute_for_index(&self, index_name: &str) -> Option<ComposablePlaintext> {
        match index_name {
            "name" => self.name.clone().try_into().ok(),
            "email#name" => (self.email.clone(), self.name.clone())
                .try_into()
                .ok(),
            _ => None,
        }
    }
}*/

impl DecryptedRecord for User {
    fn from_attributes(attributes: HashMap<String, Plaintext>) -> Self {
        Self {
            email: attributes.get("email").unwrap().try_into().unwrap(),
            name: attributes.get("name").unwrap().try_into().unwrap(),
            count: 100,
        }
    }
}

// TODO: Move all these into a proper tests module
#[cfg(test)]
mod tests {
    use super::User;
    use cryptonamo::traits::*;
    use std::any::Any;
    use std::collections::HashMap;

    #[test]
    fn test_cryptonamo_typename() {
        assert_eq!(User::type_name(), "user");
    }

    #[test]
    fn test_cryptonamo_instance() {
        let user = User::new("person@example.net", "Person Name");
        assert_eq!(user.partition_key(), "person@example.net");
        assert_eq!(
            user.protected_attributes(),
            HashMap::from([
                ("email", "person@example.net".into()),
                ("name", "Person Name".into()),
            ])
        );
        assert_eq!(
            user.plaintext_attributes(),
            HashMap::from([("count", 100i32.into()),])
        );
    }

    #[test]
    fn test_cryptonamo_index_names() {
        assert_eq!(User::protected_indexes(), vec!["email", "email#name"]);
    }

    #[test]
    fn test_cryptonamo_indexes() {
        //let index = User::index_by_name("email").unwrap();
        //let exact = index.downcast::<ExactIndex>().unwrap();
        //assert_eq!(exact.name(), "email");
    }
}
