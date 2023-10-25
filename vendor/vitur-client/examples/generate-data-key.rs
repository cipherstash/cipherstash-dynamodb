use std::error::Error;
use vitur_client::{Client, ClientKey};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let key = ClientKey::from_bytes(
        std::env::var("CLIENT_ID")
            .expect("Expected CLIENT_ID var to be set with the client key's client_id"),
        &hex::decode(std::env::var("CLIENT_KEY").expect(
            "Expected CLIENT_KEY var to be set with ClientKey key material encoded in hex",
        ))?,
    )?;

    let vitur = Client::init("http://localhost:3000".into());

    let first_key = vitur.generate_key("foo", &key, "access_token").await?;

    println!("Generated Key: {}", hex::encode(first_key.key.key));
    println!("Generated IV : {}", hex::encode(first_key.iv));
    println!();

    let second_key = vitur
        .retrieve_key(first_key.iv, "foo", &first_key.tag, &key, "access_token")
        .await?;

    assert_eq!(*first_key, second_key);

    println!("Retrieved Key: {}", hex::encode(second_key.key));

    Ok(())
}
