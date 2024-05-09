use cipherstash_dynamodb::Encryptable;

#[derive(Debug, Encryptable)]
struct User {
    #[cipherstash(query = "exact")]
    #[partition_key]
    email: String,
    __name: String
}

fn main() {}
