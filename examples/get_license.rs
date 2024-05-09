mod common;
use common::License;
use cipherstash_dynamodb::EncryptedTable;

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
    let license: Option<License> = table.get("dan@coderdan.co").await?;

    dbg!(license);

    Ok(())
}
