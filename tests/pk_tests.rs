use cryptonamo::{Encryptable, Decryptable, Searchable, EncryptedTable};
use itertools::Itertools;
use serial_test::serial;
use std::future::Future;

mod common;

#[derive(Encryptable, Decryptable, Searchable, Debug, PartialEq, Ord, PartialOrd, Eq)]
pub struct User {
    #[cryptonamo(query = "exact", compound = "pk#sk")]
    #[cryptonamo(query = "exact")]
    #[partition_key]
    pub pk: String,

    #[cryptonamo(query = "prefix", compound = "pk#sk")]
    #[cryptonamo(query = "prefix")]
    #[cryptonamo(plaintext)]
    #[sort_key]
    pub sk: String,

    #[cryptonamo(plaintext)]
    pub tag: String,
}

impl User {
    pub fn new(email: impl Into<String>, name: impl Into<String>, tag: impl Into<String>) -> Self {
        Self {
            pk: email.into(),
            sk: name.into(),
            tag: tag.into(),
        }
    }
}

async fn run_test<F: Future<Output = ()>>(mut f: impl FnMut(EncryptedTable) -> F) {
    let config = aws_config::from_env()
        .endpoint_url("http://localhost:8000")
        .load()
        .await;

    let client = aws_sdk_dynamodb::Client::new(&config);

    let table_name = "pk-sk-users";

    common::create_table(&client, table_name).await;

    let table = EncryptedTable::init(client, table_name)
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

    f(table).await;
}

#[tokio::test]
#[serial]
async fn test_query_single_exact() {
    run_test(|table| async move {
        let res: Vec<User> = table
            .query()
            .eq("pk", "dan@coderdan.co")
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
            .starts_with("sk", "Dan")
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
            .starts_with("sk", "Dan")
            .eq("pk", "dan@coderdan.co")
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
        let res: Option<User> = table
            .get(("dan@coderdan.co", "Dan Draper"))
            .await
            .expect("Failed to send");
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
            .delete::<User>(("dan@coderdan.co", "Dan Draper"))
            .await
            .expect("Failed to send");

        let res = table
            .get::<User>(("dan@coderdan.co", "Dan Draper"))
            .await
            .expect("Failed to send");
        assert_eq!(res, None);

        let res = table
            .query::<User>()
            .starts_with("sk", "Dan")
            .send()
            .await
            .expect("Failed to send");
        assert_eq!(
            res,
            vec![User::new("daniel@example.com", "Daniel Johnson", "green")]
        );

        let res = table
            .query::<User>()
            .eq("pk", "dan@coderdan.co")
            .send()
            .await
            .expect("Failed to send");
        assert_eq!(res, vec![]);

        let res = table
            .query::<User>()
            .eq("pk", "dan@coderdan.co")
            .starts_with("sk", "Dan")
            .send()
            .await
            .expect("Failed to send");
        assert_eq!(res, vec![])
    })
    .await;
}
