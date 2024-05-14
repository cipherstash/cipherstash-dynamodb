use cipherstash_dynamodb::Encryptable;

#[derive(Encryptable)]
struct User {
    #[cipherstash(compound = "email#name")]
    #[partition_key]
    email: String,
    #[cipherstash(compound = "email#name")]
    name: String,
}

fn main() {}
