use cipherstash_dynamodb::Encryptable;

#[derive(Debug, Encryptable)]
struct User {
    pk: String,
    #[partition_key]
    #[cryptonamo(query = "exact", compound = "email#name")]
    email: String,
    #[cryptonamo(query = "prefix", compound = "email#name")]
    name: String,
}

fn main() {}
