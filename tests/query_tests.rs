use cipherstash_dynamodb::{Decryptable, Encryptable, EncryptedTable, Identifiable, Searchable};
use common::{
    check_eq, check_err, check_none, fail_not_found, secondary_dataset_id, with_encrypted_table,
};
use itertools::Itertools;
use miette::Context;
use uuid::Uuid;
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

#[derive(
    Identifiable, Encryptable, Decryptable, Searchable, Debug, PartialEq, Ord, PartialOrd, Eq,
)]
#[cipherstash(sort_key_prefix = "user")]
pub struct PublicUser {
    #[partition_key]
    #[cipherstash(skip)]
    pub email: String,

    #[cipherstash(skip)]
    pub name: String,

    #[cipherstash(skip)]
    pub tag: String,

    #[cipherstash(skip)]
    pub temp: bool,
}

impl PublicUser {
    pub fn new(email: impl Into<String>, name: impl Into<String>, tag: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            email: email.into(),
            tag: tag.into(),
            temp: false,
        }
    }
}

async fn setup(table: &EncryptedTable) -> miette::Result<()> {
    table
        .put(User::new("dan@coderdan.co", "Dan Draper", "blue"))
        .await?;

    table
        .put(User::new("jane@smith.org", "Jane Smith", "red"))
        .await?;

    table
        .put(User::new("daniel@example.com", "Daniel Johnson", "green"))
        .await?;

    table
        .put_via(
            User::new("dan@coderdan.co", "Dan Draper", "red"),
            secondary_dataset_id(),
        )
        .await?;

    table
        .put_via(
            User::new("danielle@internet.org", "Danielle Rogers", "yellow"),
            secondary_dataset_id(),
        )
        .await?;

    Ok(())
}

#[tokio::test]
async fn test_query_single_exact() -> Result<(), Box<dyn std::error::Error>> {
    with_encrypted_table("query-tests", |table| async move {
        setup(&table).await?;

        let res: Vec<User> = table.query().eq("email", "dan@coderdan.co").send().await?;

        check_eq(
            res,
            vec![User::new("dan@coderdan.co", "Dan Draper", "blue")],
        )
    })
    .await
}

#[tokio::test]
async fn test_query_single_exact_via_secondary() -> Result<(), Box<dyn std::error::Error>> {
    with_encrypted_table("query-tests", |table| async move {
        setup(&table).await?;

        let res: Vec<User> = table
            .query()
            .via(secondary_dataset_id())
            .eq("email", "dan@coderdan.co")
            .send()
            .await?;

        check_eq(
            res,
            // A record with the same PK/SK but different tag (ie. not the same record as the default dataset)
            vec![User::new("dan@coderdan.co", "Dan Draper", "red")],
        )
    })
    .await
}

#[tokio::test]
async fn test_query_single_prefix() -> Result<(), Box<dyn std::error::Error>> {
    with_encrypted_table("query-tests", |table| async move {
        setup(&table).await?;

        let res: Vec<User> = table
            .query()
            .starts_with("name", "Dan")
            .send()
            .await
            .wrap_err("Failed to query")?
            .into_iter()
            .sorted()
            .collect_vec();

        check_eq(
            res,
            vec![
                User::new("dan@coderdan.co", "Dan Draper", "blue"),
                User::new("daniel@example.com", "Daniel Johnson", "green"),
            ],
        )
    })
    .await
}

#[tokio::test]
async fn test_query_single_prefix_case_insensitive() -> Result<(), Box<dyn std::error::Error>> {
    with_encrypted_table("query-tests", |table| async move {
        setup(&table).await?;

        let res: Vec<User> = table
            .query()
            .starts_with("name", "danie")
            .send()
            .await
            .wrap_err("Failed to query")?
            .into_iter()
            .sorted()
            .collect_vec();

        check_eq(
            res,
            vec![User::new("daniel@example.com", "Daniel Johnson", "green")],
        )
    })
    .await
}

/// Verifies that prefix queries are case insensitive when part of a simple query.
#[tokio::test]
async fn test_query_single_prefix_via_secondary() -> Result<(), Box<dyn std::error::Error>> {
    with_encrypted_table("query-tests", |table| async move {
        setup(&table).await?;

        let res: Vec<User> = table
            .query()
            .via(secondary_dataset_id())
            .starts_with("name", "Dan")
            .send()
            .await
            .wrap_err("Failed to query")?
            .into_iter()
            .sorted()
            .collect_vec();

        check_eq(
            res,
            vec![
                User::new("dan@coderdan.co", "Dan Draper", "red"),
                User::new("danielle@internet.org", "Danielle Rogers", "yellow"),
            ],
        )
    })
    .await
}

#[tokio::test]
async fn test_query_compound() -> Result<(), Box<dyn std::error::Error>> {
    with_encrypted_table("query-tests", |table| async move {
        setup(&table).await?;

        let res: Vec<User> = table
            .query()
            .starts_with("name", "Dan")
            .eq("email", "dan@coderdan.co")
            .send()
            .await?;

        check_eq(
            res,
            vec![User::new("dan@coderdan.co", "Dan Draper", "blue")],
        )
    })
    .await
}

/// Verifies that prefix queries are case insensitive when part of a compound query.
#[tokio::test]
async fn test_query_compound_case_insensitive() -> Result<(), Box<dyn std::error::Error>> {
    with_encrypted_table("query-tests", |table| async move {
        setup(&table).await?;

        let res: Vec<User> = table
            .query()
            .starts_with("name", "dan")
            .eq("email", "dan@coderdan.co")
            .send()
            .await?;

        check_eq(
            res,
            vec![User::new("dan@coderdan.co", "Dan Draper", "blue")],
        )
    })
    .await
}

#[tokio::test]
async fn test_query_compound_via_secondary() -> Result<(), Box<dyn std::error::Error>> {
    with_encrypted_table("query-tests", |table| async move {
        setup(&table).await?;

        let res: Vec<User> = table
            .query()
            .via(secondary_dataset_id())
            .starts_with("name", "Dan")
            .eq("email", "dan@coderdan.co")
            .send()
            .await?;

        check_eq(res, vec![User::new("dan@coderdan.co", "Dan Draper", "red")])
    })
    .await
}

#[tokio::test]
async fn test_get_by_partition_key() -> Result<(), Box<dyn std::error::Error>> {
    with_encrypted_table("query-tests", |table| async move {
        setup(&table)
            .await
            .wrap_err(format!("Setup failed (line {})", std::line!()))?;

        let res: User = table
            .get("dan@coderdan.co")
            .await
            .wrap_err(format!("User get failed (line {})", std::line!()))?
            .ok_or(fail_not_found())?;

        check_eq(res, User::new("dan@coderdan.co", "Dan Draper", "blue"))
    })
    .await
}

#[tokio::test]
async fn test_get_by_partition_key_via_secondary() -> Result<(), Box<dyn std::error::Error>> {
    with_encrypted_table("query-tests", |table| async move {
        setup(&table)
            .await
            .wrap_err(format!("Setup failed (line {})", std::line!()))?;

        let res: User = table
            .get_via("dan@coderdan.co", secondary_dataset_id())
            .await
            .wrap_err(format!("User get failed (line {})", std::line!()))?
            .ok_or(fail_not_found())?;

        check_eq(res, User::new("dan@coderdan.co", "Dan Draper", "red"))
    })
    .await
}

#[tokio::test]
async fn test_query_via_invalid() -> Result<(), Box<dyn std::error::Error>> {
    with_encrypted_table("query-tests", |table| async move {
        setup(&table).await?;

        check_err(
            table
                .query::<User>()
                // Random dataset that doesn't exist
                .via(Uuid::new_v4())
                .eq("email", "dan@coderdan.co")
                .send()
                .await,
        )
    })
    .await
}

// TODO: Move this to a separate file
#[tokio::test]
async fn test_delete() -> Result<(), Box<dyn std::error::Error>> {
    with_encrypted_table("query-tests", |table| async move {
        setup(&table).await?;

        table
            .delete::<User>("dan@coderdan.co")
            .await
            .wrap_err("Failed to delete")?;

        let res = table
            .get::<User>("dan@coderdan.co")
            .await
            .wrap_err("Failed to send GET request")?;

        check_eq(res, None)?;

        let res = table
            .query::<User>()
            .starts_with("name", "Dan")
            .send()
            .await
            .wrap_err("Failed to send")?;

        check_eq(
            res,
            vec![User::new("daniel@example.com", "Daniel Johnson", "green")],
        )?;

        let res = table
            .query::<User>()
            .eq("email", "dan@coderdan.co")
            .send()
            .await
            .wrap_err("Failed to send")?;

        check_eq(res, vec![])?;

        let res = table
            .query::<User>()
            .eq("email", "dan@coderdan.co")
            .starts_with("name", "Dan")
            .send()
            .await
            .wrap_err("Failed to send")?;

        check_eq(res, vec![])
    })
    .await
}

#[tokio::test]
async fn test_insert_retrieve_nothing_encrypted() -> Result<(), Box<dyn std::error::Error>> {
    with_encrypted_table("query-tests-nothing-encrypted", |table| async move {
        table
            .put(PublicUser::new("dan@coderdan.co", "Dan Draper", "blue"))
            .await
            .wrap_err("Failed to insert")?;

        table
            .get::<PublicUser>("dan@coderdan.co")
            .await
            .wrap_err("Failed to retrieve record")?
            .ok_or(fail_not_found())?;

        Ok(())
    })
    .await
}

#[tokio::test]
async fn test_insert_retrieve_nothing_encrypted_via_secondary(
) -> Result<(), Box<dyn std::error::Error>> {
    with_encrypted_table("query-tests-nothing-encrypted", |table| async move {
        table
            .put_via(
                PublicUser::new("dan@coderdan.co", "Dan Draper", "blue"),
                secondary_dataset_id(),
            )
            .await
            .wrap_err("Failed to insert")?;

        // Because PK is always MAC'd with the dataset specific key, we can't retrieve it without the dataset ID
        // This ensures tenant isolation even when nothing is encrypted
        table
            .get_via::<PublicUser>("dan@coderdan.co", secondary_dataset_id())
            .await
            .wrap_err("Failed to retrieve record")?
            .ok_or(fail_not_found())?;

        // Therefore, we should not be able to retrieve this record from the default dataset
        check_none(
            table
                .get::<PublicUser>("dan@coderdan.co")
                .await
                .wrap_err("Failed to retrieve record")?,
        )?;

        Ok(())
    })
    .await
}
