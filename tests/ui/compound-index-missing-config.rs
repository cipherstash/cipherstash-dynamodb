use cipherstash_dynamodb::Encryptable;

#[derive(Encryptable)]
struct User {
    #[cryptonamo(compound = "email#name")]
    #[partition_key]
    email: String,
    #[cryptonamo(compound = "email#name")]
    name: String,
}

fn main() {}
