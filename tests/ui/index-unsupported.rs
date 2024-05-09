use cipherstash_dynamodb::Encryptable;

#[derive(Encryptable)]
struct User {
    #[cipherstash(query = "blah")]
    email: String,
}

fn main() {}
