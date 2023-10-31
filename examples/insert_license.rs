mod common;
//use common::License;
use cryptonamo::EncryptedTable;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!();

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

    /*let table = EncryptedTable::init(client, "users").await?;
    table
        .put(&License::new("dan@coderdan.co", "1234567", "2027-01-10"))
        .await?;*/

    Ok(())
}
