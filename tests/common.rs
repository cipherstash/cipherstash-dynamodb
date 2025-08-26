use aws_sdk_dynamodb::{
    types::{
        AttributeDefinition, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
        ProjectionType, ProvisionedThroughput, ScalarAttributeType,
    },
    Client,
};
use cipherstash_dynamodb::EncryptedTable;
use miette::Diagnostic;
use std::{env, future::Future, sync::OnceLock};
use uuid::Uuid;

static SECONDARY_DATASET_ID: OnceLock<Uuid> = OnceLock::new();

#[derive(Debug, thiserror::Error, Diagnostic)]
#[error("Check failed: {0}")]
pub struct CheckFailed(String);

#[allow(dead_code)]
pub fn check_eq<A, B>(a: A, b: B) -> miette::Result<()>
where
    A: std::fmt::Debug + PartialEq<B>,
    B: std::fmt::Debug,
{
    if a == b {
        Ok(())
    } else {
        Err(CheckFailed(format!("Expected {:?} to equal {:?}", a, b)).into())
    }
}

#[allow(dead_code)]
pub fn check_err<R, E>(result: Result<R, E>) -> miette::Result<()>
where
    E: std::fmt::Debug,
    R: std::fmt::Debug,
{
    if result.is_err() {
        Ok(())
    } else {
        Err(CheckFailed(format!("Expected error, got {:?}", result)).into())
    }
}

#[allow(dead_code)]
pub fn check_none<R>(result: Option<R>) -> miette::Result<()>
where
    R: std::fmt::Debug,
{
    if result.is_none() {
        Ok(())
    } else {
        Err(CheckFailed(format!("Expected None, got {:?}", result)).into())
    }
}

#[allow(dead_code)]
pub fn fail_not_found() -> CheckFailed {
    CheckFailed("Record not found".into())
}

/// Run a test with an encrypted table.
/// The table will be created before the test and deleted after the test.
/// The name is used as a prefix in case its helpful to distinguish between tests.
/// A random is appended to the name to ensure uniqueness for async tests.
#[allow(dead_code)]
pub async fn with_encrypted_table<O, F: Future<Output = miette::Result<O>>>(
    table_name: &str,
    mut f: impl FnMut(EncryptedTable) -> F,
) -> Result<O, Box<dyn std::error::Error>> {
    let config = aws_config::from_env()
        .endpoint_url("http://localhost:8000")
        .load()
        .await;

    let table_name = format!("{}-{}", table_name, Uuid::new_v4());
    let client = aws_sdk_dynamodb::Client::new(&config);

    create_table(&client, &table_name).await;
    let table = EncryptedTable::init(client.clone(), &table_name).await?;
    let result = f(table).await;

    delete_table(&client, &table_name).await;
    Ok(result?)
}

pub async fn delete_table(client: &Client, table_name: &str) {
    let _ = client.delete_table().table_name(table_name).send().await;
}

pub async fn create_table(client: &Client, table_name: &str) {
    delete_table(client, table_name).await;

    client
        .create_table()
        .table_name(table_name)
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("pk")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .expect("Failed to build attribute definition"),
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("sk")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .expect("Failed to build attribute definition"),
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("term")
                .attribute_type(ScalarAttributeType::B)
                .build()
                .expect("Failed to build attribute definition"),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("pk")
                .key_type(KeyType::Hash)
                .build()
                .expect("Failed to build key schema element"),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("sk")
                .key_type(KeyType::Range)
                .build()
                .expect("Failed to build key schema element"),
        )
        .provisioned_throughput(
            ProvisionedThroughput::builder()
                .read_capacity_units(5)
                .write_capacity_units(5)
                .build()
                .expect("Failed to build provisioned throughput"),
        )
        .global_secondary_indexes(
            GlobalSecondaryIndex::builder()
                .index_name("TermIndex")
                .key_schema(
                    KeySchemaElement::builder()
                        .attribute_name("term")
                        .key_type(KeyType::Hash)
                        .build()
                        .expect("Failed to build key schema element"),
                )
                .projection(
                    Projection::builder()
                        .projection_type(ProjectionType::All)
                        .build(),
                )
                .provisioned_throughput(
                    ProvisionedThroughput::builder()
                        .read_capacity_units(5)
                        .write_capacity_units(5)
                        .build()
                        .expect("Failed to build provisioned throughput"),
                )
                .build()
                .expect("Failed to build index"),
        )
        .send()
        .await
        .expect("Failed to create table");
}

#[allow(dead_code)]
pub fn secondary_dataset_id() -> Uuid {
    *SECONDARY_DATASET_ID.get_or_init(|| {
        env::var("CS_TENANT_KEYSET_ID_1")
            .expect("CS_TENANT_KEYSET_ID_1 must be set")
            .parse()
            .expect("CS_TENANT_KEYSET_ID_1 must be a valid UUID")
    })
}

#[macro_export]
macro_rules! assert_err {
    ($cond:expr,) => {
        $crate::assert_err!($cond);
    };
    ($cond:expr) => {
        match $cond {
            Ok(t) => {
                panic!("assertion failed, expected Err(..), got Ok({:?})", t);
            },
            Err(e) => e,
        }
    };
    ($cond:expr, $($arg:tt)+) => {
        match $cond {
            Ok(t) => {
                panic!("assertion failed, expected Err(..), got Ok({:?}): {}", t, format_args!($($arg)+));
            },
            Err(e) => e,
        }
    };
}

#[macro_export]
macro_rules! assert_none {
    ($cond:expr,) => {
        $crate::assert_none!($cond);
    };
    ($cond:expr) => {
        match $cond {
            Some(t) => {
                panic!("assertion failed, expected Err(..), got Ok({:?})", t);
            },
            None => (),
        }
    };
    ($cond:expr, $($arg:tt)+) => {
        match $cond {
            Ok(t) => {
                panic!("assertion failed, expected None, got Some({:?}): {}", t, format_args!($($arg)+));
            },
            Err(e) => (),
        }
    };
}
