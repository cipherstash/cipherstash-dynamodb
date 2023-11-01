use cryptonamo::Cryptonamo;

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
