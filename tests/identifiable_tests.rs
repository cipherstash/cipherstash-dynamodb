use cipherstash_dynamodb::traits::*;
use cipherstash_dynamodb::*;
use serial_test::serial;
use std::future::Future;

mod common;

#[derive(Debug, Encryptable, Decryptable)]
pub struct User {
    name: String,
    age: u64,
}

// implement a noop Searchable for user as there are no indexes
impl Searchable for User {}

impl Identifiable for User {
    type PrimaryKey = PkSk;

    fn type_name() -> std::borrow::Cow<'static, str> {
        std::any::type_name::<Self>().to_lowercase().into()
    }

    fn sort_key_prefix() -> Option<std::borrow::Cow<'static, str>> {
        Some(Self::type_name())
    }

    fn get_primary_key(&self) -> Self::PrimaryKey {
        PkSk("user".to_string(), self.name.to_string())
    }
}

#[tokio::test]
#[serial]
async fn test_round_trip_user() {
    run_test(|table| async move {
        table
            .put(User {
                name: "Sarah".to_string(),
                age: 100,
            })
            .await
            .expect("failed to put Sarah");

        table
            .put(User {
                name: "John".to_string(),
                age: 100,
            })
            .await
            .expect("failed to put John");

        let sarah: User = table
            .get(("user", "Sarah"))
            .await
            .expect("failed to get Sarah")
            .unwrap();

        let john: User = table
            .get(("user", "John"))
            .await
            .expect("failed to get Sarah")
            .unwrap();

        assert_eq!(sarah.name, "Sarah");
        assert_eq!(john.name, "John");
    })
    .await;
}

async fn run_test<F: Future<Output = ()>>(mut f: impl FnMut(EncryptedTable) -> F) {
    let config = aws_config::from_env()
        .endpoint_url("http://localhost:8000")
        .load()
        .await;

    let client = aws_sdk_dynamodb::Client::new(&config);

    let table_name = "identifiable-tests";

    common::create_table(&client, table_name).await;

    let table = EncryptedTable::init(client, table_name)
        .await
        .expect("Failed to init table");

    f(table).await;
}
