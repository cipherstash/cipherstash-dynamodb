use cipherstash_dynamodb::Encryptable;

#[derive(Encryptable)]
struct User {
    #[cipherstash(query = "exact", compound = "email#name")]
    email: String,
    #[cipherstash(query = "exact", compound = "email#name")]
    name: String,
    #[cipherstash(query = "exact", compound = "email#name")]
    age: usize,
}

fn main() {}
