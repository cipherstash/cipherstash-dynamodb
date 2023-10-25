use std::error::Error;
use vitur_client::{Client, ClientKey};
use vitur_config::DatasetConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let access_token = std::env::var("ACCESS_TOKEN")
        .expect("Expected ACCESS_TOKEN var to be set with the a well formed Vitur JWT");

    let key = ClientKey::from_bytes(
        std::env::var("CLIENT_ID")
            .expect("Expected CLIENT_ID var to be set with the client key's client_id"),
        &hex::decode(std::env::var("CLIENT_KEY").expect(
            "Expected CLIENT_KEY var to be set with ClientKey key material encoded in hex",
        ))?,
    )?;

    let vitur = Client::init("http://localhost:3000".into());

    let dataset_config = DatasetConfig::init();

    println!("Saving config: {:?}", dataset_config);

    vitur
        .save_config(dataset_config, &key, &access_token)
        .await?;

    println!("Config saved!");

    let config = vitur.load_config(&key, &access_token).await?;

    println!("Loaded config: {:?}", config);

    Ok(())
}
