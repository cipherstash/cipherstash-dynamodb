use cipherstash_dynamodb::Encryptable;

#[derive(Debug, Encryptable)]
struct User {
    #[cipherstash(query = "prefix", compound = "email#name")]
    #[partition_key]
    email: String,
    #[cipherstash(query = "blah", compound = "email#name")]
    name: String,
}

fn main() {}
