mod common;
use crate::common::UserResultByName;
use cryptonamo::{encrypted_table::EncryptedTable, Plaintext};

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

    let table = EncryptedTable::init(client, "users").await;

    let results: Vec<UserResultByName> = table
        .query_match_exact(
            ("name", "Dan Drap"),
            (
                "email",
                &Plaintext::Utf8Str(Some("dan@coderdan.co".to_string())),
            ),
        )
        .await;

    dbg!(results);

    Ok(())
}
