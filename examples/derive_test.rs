use tokio;

use cryptonamo::EncryptedTable;
use cryptonamo_derive::Cryptonamo;

#[derive(Cryptonamo, Debug)]
#[cryptonamo(partition_key = "email")]
struct User {
    #[cryptonamo(query = "prefix", compound = "email#name")]
    name: String,

    #[cryptonamo(query = "exact", compound = "email#name")]
    email: String,
}

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

    table
        .put(&User {
            name: "Jane Smith".to_string(),
            email: "jane@smith.org".to_string(),
        })
        .await?;

    // table
    //     .put(&User {
    //         name: "Dan Draper".to_string(),
    //         email: "dan@coderdan.co".to_string(),
    //     })
    //     .await?;

    // table
    //     .put(&User {
    //         name: "Daniel Johnson".to_string(),
    //         email: "daniel@example.com".to_string(),
    //     })
    //     .await?;


    Ok(())
}
