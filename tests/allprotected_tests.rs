use chrono::NaiveDate;
use cipherstash_dynamodb::{Decryptable, Encryptable, EncryptedTable, Identifiable, Searchable};
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

    pub dob: NaiveDate,
}

impl User {
    pub fn new(email: impl Into<String>, name: impl Into<String>, dob: NaiveDate) -> Self {
        Self {
            name: name.into(),
            email: email.into(),
            dob,
        }
    }
}

async fn run_test<F: Future<Output = ()>>(mut f: impl FnMut(EncryptedTable) -> F) {
    let config = aws_config::from_env()
        .endpoint_url("http://localhost:8000")
        .load()
        .await;

    let client = aws_sdk_dynamodb::Client::new(&config);

    let table_name = "test-users-plaintext-email";

    common::create_table(&client, table_name).await;
    let table = EncryptedTable::init(client, table_name)
        .await
        .expect("Failed to init table");

    table
        .put(User::new(
            "dan@coderdan.co",
            "Dan Draper",
            NaiveDate::from_ymd_opt(2000, 1, 10).unwrap(),
        ))
        .await
        .expect("Failed to insert Dan");

    /*table
        .put(User::new("jane@smith.org", "Jane Smith", NaiveDate::from_ymd_opt(1990, 2, 20).unwrap()))
        .await
        .expect("Failed to insert Jane");

    table
        .put(User::new("daniel@example.com", "Daniel Johnson", NaiveDate::from_ymd_opt(1980, 3, 30).unwrap()))
        .await
        .expect("Failed to insert Daniel");*/

    f(table).await;
}

#[tokio::test]
#[serial]
async fn test_get() {
    run_test(|table| async move {
        let res: Option<User> = table
            .get("dan@coderdan.co")
            .await
            .expect("Failed to get user");

        assert_eq!(
            res,
            Some(User::new(
                "dan@coderdan.co",
                "Dan Draper",
                NaiveDate::from_ymd_opt(2000, 1, 10).unwrap()
            ))
        );
    })
    .await;
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
            vec![User::new(
                "dan@coderdan.co",
                "Dan Draper",
                NaiveDate::from_ymd_opt(2000, 1, 10).unwrap()
            )]
        );
    })
    .await;
}
