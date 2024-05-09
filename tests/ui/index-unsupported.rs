use cipherstash_dynamodb::Encryptable;

#[derive(Encryptable)]
struct User {
    #[cryptonamo(query = "blah")]
    email: String,
}

fn main() {}
