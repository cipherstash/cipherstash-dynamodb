use cipherstash_dynamodb::{Encryptable, Identifiable};

#[derive(Debug, Encryptable, Identifiable)]
struct User {
    #[partition_key]
    pk: String,
    #[cipherstash(query = "exact", compound = "email#name")]
    email: String,
    #[cipherstash(query = "prefix", compound = "email#name")]
    name: String,
}

fn main() {}
