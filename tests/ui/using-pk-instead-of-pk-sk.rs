use cipherstash_dynamodb::{Decryptable, Encryptable, Searchable};
use cipherstash_dynamodb::EncryptedTable;

#[derive(Debug, Encryptable, Decryptable, Searchable)]
struct User {
    #[cryptonamo(query = "exact")]
    #[partition_key]
    email: String,

    #[cryptonamo(query = "exact")]
    #[sort_key]
    name: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = aws_config::from_env()
        .endpoint_url("http://localhost:8000")
        .load()
        .await;

    let client = aws_sdk_dynamodb::Client::new(&config);
    let table = EncryptedTable::init(client, "users").await?;

    let user: Option<User> = table.get("user@example.com").await?;

    Ok(())
}
