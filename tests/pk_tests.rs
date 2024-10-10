use cipherstash_dynamodb::{Decryptable, Encryptable, EncryptedTable, Error, Identifiable, Searchable};
use itertools::Itertools;
use miette::{Report, IntoDiagnostic};
use serial_test::serial;
use std::future::Future;

mod common;

#[derive(
    Identifiable, Encryptable, Decryptable, Searchable, Debug, PartialEq, Ord, PartialOrd, Eq,
)]
pub struct User {
    #[cipherstash(query = "exact", compound = "pk#sk")]
    #[cipherstash(query = "exact")]
    #[partition_key]
    pub pk: String,

    #[cipherstash(query = "prefix", compound = "pk#sk")]
    #[cipherstash(query = "prefix")]
    // TODO: also test if the sort key is encrypted
    // TODO: Can we add some unit tests!?
    #[cipherstash(plaintext)]
    #[sort_key]
    pub sk: String,

    #[cipherstash(plaintext)]
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

type TestResult = Result<(), Report>;

async fn run_test<F>(mut f: impl FnMut(EncryptedTable) -> F) -> Result<(), Error>
where
    F: Future<Output = Result<(), Error>>,
{
    let config = aws_config::from_env()
        .endpoint_url("http://localhost:8000")
        .load()
        .await;

    let client = aws_sdk_dynamodb::Client::new(&config);

    let table_name = "pk-sk-users";

    common::create_table(&client, table_name).await;

    let table = EncryptedTable::init(client, table_name)
        .await?;

    table
        .put(User::new("dan@coderdan.co", "Dan Draper", "blue"))
        .await?;

    table
        .put(User::new("jane@smith.org", "Jane Smith", "red"))
        .await?;

    table
        .put(User::new("daniel@example.com", "Daniel Johnson", "green"))
        .await?;

    f(table).await
}

#[tokio::test]
#[serial]
async fn test_query_single_exact() -> TestResult {
    run_test(|table| async move {
        let res: Vec<User> = table
            .query()
            .eq("pk", "dan@coderdan.co")
            .send()
            .await?;

        assert_eq!(
            res,
            vec![User::new("dan@coderdan.co", "Dan Draper", "blue")]
        );

        Ok(())
    })
    .await
    .into_diagnostic()
}

#[tokio::test]
#[serial]
async fn test_query_single_prefix() -> TestResult {
    run_test(|table| async move {
        let res: Vec<User> = table
            .query()
            .starts_with("sk", "Dan")
            .send()
            .await?
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

        Ok(())
    })
    .await
    .into_diagnostic()
}

#[tokio::test]
#[serial]
async fn test_query_compound() -> TestResult {
    run_test(|table| async move {
        let res: Vec<User> = table
            .query()
            .starts_with("sk", "Dan")
            .eq("pk", "dan@coderdan.co")
            .send()
            .await?;

        assert_eq!(
            res,
            vec![User::new("dan@coderdan.co", "Dan Draper", "blue")]
        );

        Ok(())
    })
    .await
    .into_diagnostic()
}

#[tokio::test]
#[serial]
async fn test_get_by_partition_key() -> TestResult {
    run_test(|table| async move {
        let res: Option<User> = table.get(("dan@coderdan.co", "Dan Draper")).await?;

        assert_eq!(
            res,
            Some(User::new("dan@coderdan.co", "Dan Draper", "blue"))
        );

        Ok(())
    })
    .await
    .into_diagnostic()
}

#[tokio::test]
#[serial]
// FIXME: These tests would be better if the run_test function returned a diagnostic result
async fn test_delete() -> TestResult {
    run_test(|table| async move {
        table
            .delete::<User>(("dan@coderdan.co", "Dan Draper"))
            .await?;

        let res = table
            .get::<User>(("dan@coderdan.co", "Dan Draper"))
            .await?;
        
        assert_eq!(res, None);

        let res = table
            .query::<User>()
            .starts_with("sk", "Dan")
            .send()
            .await?;

        assert_eq!(
            res,
            vec![User::new("daniel@example.com", "Daniel Johnson", "green")]
        );

        let res = table
            .query::<User>()
            .eq("pk", "dan@coderdan.co")
            .send()
            .await?;

        assert_eq!(res, vec![]);

        let res = table
            .query::<User>()
            .eq("pk", "dan@coderdan.co")
            .starts_with("sk", "Dan")
            .send()
            .await?;

        assert_eq!(res, vec![]);

        Ok(())
    })
    .await
    .into_diagnostic()
}
