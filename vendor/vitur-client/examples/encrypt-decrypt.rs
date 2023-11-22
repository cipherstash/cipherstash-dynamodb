use std::error::Error;
use vitur_client::{Client, ClientKey, EncryptPayload};

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

    let data = vec![1, 2, 3, 4, 5, 6];

    let encrypted = vitur
        .encrypt_single(
            EncryptPayload::new(&data, "foo"),
            &key,
            "access_token",
        )
        .await
        .expect("failed to encrypt");

    println!("Record Iv: {:?}", hex::encode(encrypted.iv));
    println!(
        "Record Ciphertext: {:?}",
        hex::encode(&encrypted.ciphertext)
    );

    let decrypted = vitur
        .decrypt_single(encrypted, &key, "access_token")
        .await
        .expect("failed to decrypt");

    println!("Decrypted: {:?}", decrypted);

    Ok(())
}
