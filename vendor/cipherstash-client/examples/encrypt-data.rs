use anyhow::Result;
use cipherstash_client::config::{
    console_config::ConsoleConfig, idp_config::IdpConfig, vitur_config::ViturConfig,
};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(long)]
    descriptor: String,

    #[arg(long)]
    message: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let console_config = ConsoleConfig::builder().with_env().build()?;

    let idp_config = IdpConfig::builder().with_env().build()?;

    let vitur_config = ViturConfig::builder()
        .console_config(&console_config)
        .idp_config(&idp_config)
        .with_env()
        .build_with_client_key()?;

    let vitur = vitur_config.create_vitur();

    let record = vitur
        .encrypt_single(vitur_client::EncryptPayload {
            msg: args.message.as_bytes(),
            descriptor: &args.descriptor,
        })
        .await?;

    println!("Vitur: {}", vitur_config.base_url());
    println!("Workspace: {}", vitur_config.base_url());
    println!("Message: {}", args.message);
    println!("Descriptor: {}", args.descriptor);
    println!("---");
    println!("Encrypted: {}", hex::encode(record.to_vec()?));

    Ok(())
}
