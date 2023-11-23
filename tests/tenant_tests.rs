use cryptonamo::{Decryptable, Encryptable, EncryptedTable, PkSk, Searchable};
use itertools::Itertools;
use serial_test::serial;
use std::future::Future;

mod common;

#[derive(Encryptable, Decryptable, Searchable, Debug, PartialEq, Ord, PartialOrd, Eq)]
#[cryptonamo(sort_key_prefix = "user-something")]
pub struct User {
    #[partition_key]
    pub tenant_id: String,

    #[sort_key]
    #[cryptonamo(query = "exact", compound = "email#name")]
    #[cryptonamo(query = "exact")]
    pub email: String,

    #[cryptonamo(query = "prefix", compound = "email#name")]
    #[cryptonamo(query = "prefix")]
    pub name: String,
}

impl User {
    fn new(
        tenant_id: impl Into<String>,
        email: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
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

    let table = "test-users-tenant";

    common::create_table(&client, table, "tenant_id").await;

    let table = EncryptedTable::init(client, table)
        .await
        .expect("Failed to init table");

    table
        .put(User::new("first-tenant", "dan@coderdan.co", "Dan Draper"))
        .await
        .expect("Failed to insert Dan");

    table
        .put(User::new("first-tenant", "jane@smith.org", "Jane Smith"))
        .await
        .expect("Failed to insert Jane");

    table
        .put(User::new(
            "first-tenant",
            "daniel@example.com",
            "Daniel Johnson",
        ))
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
            .eq("email", "dan@coderdan.co")
            .send()
            .await
            .expect("Failed to query");

        assert_eq!(
            res,
            vec![User::new("first-tenant", "dan@coderdan.co", "Dan Draper",)]
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
                User::new("first-tenant", "dan@coderdan.co", "Dan Draper"),
                User::new("first-tenant", "daniel@example.com", "Daniel Johnson",)
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
            vec![User::new("first-tenant", "dan@coderdan.co", "Dan Draper")]
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn test_get_by_partition_key() {
    run_test(|table| async move {
        let res: Option<User> = table
            .get(PkSk::new("first-tenant", "dan@coderdan.co"))
            .await
            .expect("Failed to send");
        assert_eq!(
            res,
            Some(User::new("first-tenant", "dan@coderdan.co", "Dan Draper",))
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn test_delete() {
    run_test(|table| async move {
        table
            .delete::<User>(PkSk::new("first-tenant", "dan@coderdan.co"))
            .await
            .expect("Failed to send");

        let res = table
            .get::<User>(PkSk::new("first-tenant", "dan@coderdan.co"))
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
            vec![User::new(
                "first-tenant",
                "daniel@example.com",
                "Daniel Johnson"
            )]
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
