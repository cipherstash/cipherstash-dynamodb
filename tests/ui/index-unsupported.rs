use cryptonamo::Encryptable;

#[derive(Encryptable)]
struct User {
    #[cryptonamo(query = "blah")]
    email: String,
}

fn main() {}
