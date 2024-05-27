use aws_sdk_dynamodb::types::{Put, TransactWriteItem};
use cipherstash_dynamodb::{Decryptable, Encryptable, EncryptedTable, Searchable};
use itertools::Itertools;
use serial_test::serial;
use std::future::Future;

mod common;

#[derive(Encryptable, Decryptable, Searchable, Debug, PartialEq, Ord, PartialOrd, Eq)]
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

#[allow(dead_code)]
async fn regrenerate_data(client: &aws_sdk_dynamodb::Client, table_name: &str) {
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

    let all_items = client
        .scan()
        .table_name(table_name)
        .send()
        .await
        .unwrap()
        .items()
        .iter()
        .cloned()
        .map(serde_dynamo::Item::from)
        .collect_vec();

    std::fs::write(
        "./tests/query_regression_data.json",
        serde_json::to_string_pretty(&all_items).expect("Failed to stringify dynamo records"),
    )
    .expect("Failed to update query regression test data");
}

async fn run_test<F: Future<Output = ()>>(mut f: impl FnMut(EncryptedTable) -> F) {
    let config = aws_config::from_env()
        .endpoint_url("http://localhost:8000")
        .load()
        .await;

    let client = aws_sdk_dynamodb::Client::new(&config);

    let table_name = "test-users-pk";

    common::create_table(&client, table_name).await;

    let table = EncryptedTable::init(client.clone(), table_name)
        .await
        .expect("Failed to init table");

    // Uncomment to regenerate the query_regression data json file
    // regrenerate_data(&client, table_name).await;

    let items: Vec<serde_dynamo::Item> =
        serde_json::from_str(include_str!("./query_regression_data.json"))
            .expect("Failed to parse data");

    client
        .transact_write_items()
        .set_transact_items(Some(
            items
                .into_iter()
                .map(|item| {
                    TransactWriteItem::builder()
                        .put(
                            Put::builder()
                                .table_name(table_name)
                                .set_item(Some(item.into()))
                                .build()
                                .expect("failed to build put"),
                        )
                        .build()
                })
                .collect(),
        ))
        .send()
        .await
        .expect("failed to send");

    f(table).await;
}

#[tokio::test]
#[serial]
async fn test_query_single_exact() {
    run_test(|table| async move {
        let res: Vec<User> = table
            .query()
            .eq("email", "dan@coderdan.co")
            .send()
            .await
            .expect("Failed to query");

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
    run_test(|table| async move {
        let res: Vec<User> = table
            .query()
            .starts_with("name", "Dan")
            .send()
            .await
            .expect("Failed to query")
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
    run_test(|table| async move {
        let res: Vec<User> = table
            .query()
            .starts_with("name", "Dan")
            .eq("email", "dan@coderdan.co")
            .send()
            .await
            .expect("Failed to query");

        assert_eq!(
            res,
            vec![User::new("dan@coderdan.co", "Dan Draper", "blue")]
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn test_get_by_partition_key() {
    run_test(|table| async move {
        let res: Option<User> = table.get("dan@coderdan.co").await.expect("Failed to send");
        assert_eq!(
            res,
            Some(User::new("dan@coderdan.co", "Dan Draper", "blue"))
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn test_delete() {
    run_test(|table| async move {
        table
            .delete::<User>("dan@coderdan.co")
            .await
            .expect("Failed to send");

        let res = table
            .get::<User>("dan@coderdan.co")
            .await
            .expect("Failed to send");
        assert_eq!(res, None);

        let res = table
            .query::<User>()
            .starts_with("name", "Dan")
            .send()
            .await
            .expect("Failed to send");
        assert_eq!(
            res,
            vec![User::new("daniel@example.com", "Daniel Johnson", "green")]
        );

        let res = table
            .query::<User>()
            .eq("email", "dan@coderdan.co")
            .send()
            .await
            .expect("Failed to send");
        assert_eq!(res, vec![]);

        let res = table
            .query::<User>()
            .eq("email", "dan@coderdan.co")
            .starts_with("name", "Dan")
            .send()
            .await
            .expect("Failed to send");
        assert_eq!(res, vec![])
    })
    .await;
}
