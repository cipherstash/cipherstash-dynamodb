use cipherstash_dynamodb::Encryptable;

#[derive(Debug, Encryptable)]
struct User {
    #[cipherstash(query = "exact", compound = "email#name")]
    #[partition_key]
    email: String,
    #[cipherstash(query = "prefix", compound = "email#name")]
    #[sort_key]
    name: String,

    sk: String,
}

fn main() {}
