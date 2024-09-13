use cipherstash_dynamodb::{
    Decryptable, Encryptable, EncryptedTable, Identifiable, Pk, Searchable,
};
use serial_test::serial;
use std::{borrow::Cow, future::Future};

mod common;

#[derive(Encryptable, Decryptable, Searchable, Debug, PartialEq, Ord, PartialOrd, Eq)]
pub struct User {
    #[cipherstash(query = "exact")]
    encrypted: Option<String>,
    #[cipherstash(plaintext)]
    plaintext: Option<String>,
}

impl Identifiable for User {
    type PrimaryKey = Pk;

    fn get_primary_key(&self) -> Self::PrimaryKey {
        Pk("user".into())
    }

    fn type_name() -> Cow<'static, str> {
        "user".into()
    }

    fn sort_key_prefix() -> Option<Cow<'static, str>> {
        None
    }
}

#[derive(Encryptable, Decryptable, Searchable, Debug, PartialEq, Ord, PartialOrd, Eq)]
pub struct Empty {}

impl Identifiable for Empty {
    type PrimaryKey = Pk;

    fn get_primary_key(&self) -> Self::PrimaryKey {
        Pk("user".into())
    }

    fn type_name() -> Cow<'static, str> {
        "user".into()
    }

    fn sort_key_prefix() -> Option<Cow<'static, str>> {
        None
    }
}

async fn run_test<F: Future<Output = ()>>(mut f: impl FnMut(EncryptedTable) -> F) {
    let config = aws_config::from_env()
        .endpoint_url("http://localhost:8000")
        .load()
        .await;

    let client = aws_sdk_dynamodb::Client::new(&config);

    let table_name = "empty-record-load";

    common::create_table(&client, table_name).await;

    let table = EncryptedTable::init(client, table_name)
        .await
        .expect("Failed to init table");

    table
        .put(Empty {})
        .await
        .expect("Failed to insert empty record");

    f(table).await;
}

#[tokio::test]
#[serial]
async fn test_load_from_empty() {
    run_test(|table| async move {
        table
            .get::<User>(Pk("user".into()))
            .await
            .expect("failed to get user");
    })
    .await
}
