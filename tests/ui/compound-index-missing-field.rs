use cipherstash_dynamodb::Encryptable;

#[derive(Encryptable)]
struct User {
    email: String,
    #[cipherstash(query = "exact", compound = "email#name")]
    name: String,
}

fn main() {}
