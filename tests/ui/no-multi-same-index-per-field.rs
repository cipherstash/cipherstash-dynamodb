use cipherstash_dynamodb::Encryptable;

#[derive(Encryptable)]
struct User {
    #[partition_key]
    email: String,
    #[cipherstash(query = "exact")]
    #[cipherstash(query = "exact")]
    name: String,
}

fn main() {}
