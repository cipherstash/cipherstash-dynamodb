use cipherstash_dynamodb::{
    encrypted_table::ScopedZeroKmsCipher, Decryptable, Encryptable, EncryptedTable, Identifiable,
    QueryBuilder, Searchable,
};
use itertools::Itertools;
use serial_test::serial;
use std::future::Future;
mod common;

#[derive(
    Identifiable, Encryptable, Decryptable, Searchable, Debug, PartialEq, Ord, PartialOrd, Eq,
)]
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
    pub tag: String,

    #[cipherstash(skip)]
    pub temp: bool,
}

impl User {
    pub fn new(email: impl Into<String>, name: impl Into<String>, tag: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            email: email.into(),
            tag: tag.into(),
            temp: false,
        }
    }
}

async fn run_test<F: Future<Output = ()>>(
    mut f: impl FnMut(aws_sdk_dynamodb::Client, String) -> F,
) {
    let config = aws_config::from_env()
        .endpoint_url("http://localhost:8000")
        .load()
        .await;

    let client = aws_sdk_dynamodb::Client::new(&config);

    let table_name = "test-users-direct-query-builder";

    common::create_table(&client, table_name).await;

    let table = EncryptedTable::init(client.clone(), table_name)
        .await
        .expect("Failed to init table");

    table
        .put(User::new("dan@coderdan.co", "Dan Draper", "blue"))
        .await
        .expect("Failed to insert Dan");

    table
        .put(User::new("jane@smith.org", "Jane Smith", "red"))
        .await
        .expect("Failed to insert Jane");

    table
        .put(User::new("daniel@example.com", "Daniel Johnson", "green"))
        .await
        .expect("Failed to insert Daniel");

    f(client, table_name.to_string()).await;
}

#[tokio::test]
#[serial]
async fn test_query_single_exact() {
    run_test(|client, name| async move {
        let table = EncryptedTable::init_headless()
            .await
            .expect("failed to init table");

        let query = QueryBuilder::<User>::new()
            .eq("email", "dan@coderdan.co")
            .build()
            .expect("failed to build query");

        let scoped_cipher = ScopedZeroKmsCipher::init(table.cipher(), None)
            .await
            .unwrap();

        let term = query
            .encrypt(&scoped_cipher)
            .await
            .expect("failed to encrypt query");

        let query = client
            .query()
            .table_name(name)
            .index_name("TermIndex")
            .key_condition_expression("term = :term")
            .expression_attribute_values(":term", term);

        let result = query.send().await.expect("failed to send");

        let items = result.items.unwrap();

        let res: Vec<User> = table
            .decrypt_all(items)
            .await
            .expect("failed to decrypt")
            .into_iter()
            .sorted()
            .collect_vec();

        assert_eq!(
            res,
            vec![User::new("dan@coderdan.co", "Dan Draper", "blue")]
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn test_query_single_prefix() {
    run_test(|client, name| async move {
        let table = EncryptedTable::init_headless()
            .await
            .expect("failed to init table");

        let scoped_cipher = ScopedZeroKmsCipher::init(table.cipher(), None)
            .await
            .unwrap();

        let query = QueryBuilder::<User>::new()
            .starts_with("name", "Dan")
            .build()
            .expect("failed to build query");

        let term = query
            .encrypt(&scoped_cipher)
            .await
            .expect("failed to encrypt query");

        let query = client
            .query()
            .table_name(name)
            .index_name("TermIndex")
            .key_condition_expression("term = :term")
            .expression_attribute_values(":term", term);

        let result = query.send().await.expect("failed to send");

        let items = result.items.unwrap();

        let res: Vec<User> = table
            .decrypt_all(items)
            .await
            .expect("failed to decrypt")
            .into_iter()
            .sorted()
            .collect_vec();

        assert_eq!(
            res,
            vec![
                User::new("dan@coderdan.co", "Dan Draper", "blue"),
                User::new("daniel@example.com", "Daniel Johnson", "green")
            ]
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn test_query_compound() {
    run_test(|client, name| async move {
        let table = EncryptedTable::init_headless()
            .await
            .expect("failed to init table");

        let query = QueryBuilder::<User>::new()
            .starts_with("name", "Dan")
            .eq("email", "dan@coderdan.co")
            .build()
            .expect("failed to build query");

        let scoped_cipher = ScopedZeroKmsCipher::init(table.cipher(), None)
            .await
            .unwrap();

        let term = query
            .encrypt(&scoped_cipher)
            .await
            .expect("failed to encrypt query");

        let query = client
            .query()
            .table_name(name)
            .index_name("TermIndex")
            .key_condition_expression("term = :term")
            .expression_attribute_values(":term", term);

        let result = query.send().await.expect("failed to send");

        let items = result.items.unwrap();

        let res: Vec<User> = table
            .decrypt_all(items)
            .await
            .expect("failed to decrypt")
            .into_iter()
            .sorted()
            .collect_vec();

        assert_eq!(
            res,
            vec![User::new("dan@coderdan.co", "Dan Draper", "blue")]
        );
    })
    .await;
}
