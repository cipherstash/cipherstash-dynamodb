use aws_sdk_dynamodb::{
    types::{
        AttributeDefinition, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
        ProjectionType, ProvisionedThroughput, ScalarAttributeType,
    },
    Client,
};

pub async fn create_table(client: &Client, table_name: &str) {
    let _ = client.delete_table().table_name(table_name).send().await;

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