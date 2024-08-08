use cipherstash_dynamodb::{Encryptable, Identifiable};

#[derive(Debug, Identifiable, Encryptable)]
struct User {
    #[cipherstash(query = "exact", compound = "email#name")]
    #[partition_key]
    email: String,
    #[cipherstash(query = "prefix", compound = "email#name")]
    name: String,
}

fn main() {}
