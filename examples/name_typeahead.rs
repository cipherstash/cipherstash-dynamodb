mod common;
use crate::common::{User, UserResultByName};
use cryptonamo::{encrypted_table::EncryptedTable, EncryptedRecord};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .without_time()
        .init();

    env_logger::init();

    let config = aws_config::from_env()
        .endpoint_url("http://localhost:8000")
        .load()
        .await;

    let client = aws_sdk_dynamodb::Client::new(&config);

    let table = EncryptedTable::init(client, "users").await?;
    // TODO: there is no fuzzy index for this just yet
    // not sure how that would be configured
    let results: Vec<UserResultByName> =
        table.query(User::find_where("name", "Jane Smith")).await?;

    dbg!(results);

    Ok(())
}
