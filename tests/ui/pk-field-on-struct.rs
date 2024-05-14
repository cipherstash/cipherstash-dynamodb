use cipherstash_dynamodb::Encryptable;

#[derive(Debug, Encryptable)]
struct User {
    #[partition_key]
    pk: String,
    #[cipherstash(query = "exact", compound = "email#name")]
    email: String,
    #[cipherstash(query = "prefix", compound = "email#name")]
    name: String,
}

fn main() {}
