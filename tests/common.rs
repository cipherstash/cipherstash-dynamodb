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
                .attribute_type(ScalarAttributeType::S)
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
