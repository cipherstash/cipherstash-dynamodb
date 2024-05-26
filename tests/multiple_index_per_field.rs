use cipherstash_dynamodb::{Decryptable, Encryptable, EncryptedTable, Searchable};
use serial_test::serial;
use std::future::Future;

mod common;

#[derive(Encryptable, Decryptable, Searchable, Debug, PartialEq)]
pub struct User {
    #[partition_key]
    pub email: String,

    #[cipherstash(query = "exact")]
    #[cipherstash(query = "prefix")]
    pub name: String,
}

impl User {
    fn new(email: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            name: name.into(),
        }
    }
}

async fn run_test<F: Future<Output = ()>>(mut f: impl FnMut(EncryptedTable) -> F) {
    let config = aws_config::from_env()
        .endpoint_url("http://localhost:8000")
        .load()
        .await;

    let client = aws_sdk_dynamodb::Client::new(&config);

    let table_name = "test-users-pk";

    common::create_table(&client, table_name).await;

    let table = EncryptedTable::init(client, table_name)
        .await
        .expect("Failed to init table");

    table
        .put(User::new("dan@coderdan.co", "Dan Draper"))
        .await
        .expect("Failed to insert Dan");

    table
        .put(User::new("jane@smith.org", "Jane Smith"))
        .await
        .expect("Failed to insert Jane");

    table
        .put(User::new("daniel@example.com", "Daniel Johnson"))
        .await
        .expect("Failed to insert Daniel");

    f(table).await;
}

#[tokio::test]
#[serial]
async fn test_query_single_exact() {
    run_test(|table| async move {
        let res: Vec<User> = table
            .query()
            .eq("name", "Dan Draper")
            .send()
            .await
            .expect("Failed to query");

        assert_eq!(res, vec![User::new("dan@coderdan.co", "Dan Draper")]);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn test_query_exact_no_records() {
    run_test(|table| async move {
        let res: Vec<User> = table
            .query()
            .eq("name", "Dan")
            .send()
            .await
            .expect("Failed to query");

        assert_eq!(res, vec![]);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn test_query_prefix() {
    run_test(|table| async move {
        let res: Vec<User> = table
            .query()
            .starts_with("name", "Dan")
            .send()
            .await
            .expect("Failed to query");

        assert_eq!(
            res,
            vec![
                User::new("dan@coderdan.co", "Dan Draper"),
                User::new("daniel@example.com", "Daniel Johnson")
            ]
        );
    })
    .await;
}
