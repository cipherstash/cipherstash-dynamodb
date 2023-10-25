use std::{error::Error, time::Instant};
use vitur_client::{Client, ClientKey, GenerateKeyPayload, RetrieveKeyPayload};

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

    let vals = [10, 100, 200, 500, 1000, 2000, 3000, 4000, 5000];

    for val in vals {
        let now = Instant::now();

        let keys = vitur
            .generate_keys(
                std::iter::repeat_with(|| GenerateKeyPayload { descriptor: "blah" }).take(val),
                &key,
                "access_token",
            )
            .await?;

        let millis = now.elapsed().as_millis();

        println!(
            "Generating {} keys took {}ms. That's {}ms per key.",
            val,
            millis,
            millis as f64 / val as f64
        );

        let now = Instant::now();

        let retrieved_keys = vitur
            .retrieve_keys(
                keys.iter().map(|x| RetrieveKeyPayload {
                    iv: x.iv,
                    descriptor: "blah",
                    tag: &x.tag,
                }),
                &key,
                "access_token",
            )
            .await?;

        let millis = now.elapsed().as_millis();

        println!(
            "Retrieving {} keys took {}ms. That's {}ms per key.\n\n",
            val,
            millis,
            millis as f64 / val as f64
        );

        assert_eq!(
            retrieved_keys,
            keys.into_iter().map(|x| x.key).collect::<Vec<_>>()
        );
    }

    Ok(())
}
