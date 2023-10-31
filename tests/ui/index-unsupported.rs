use cryptonamo::Cryptonamo;

#[derive(Cryptonamo)]
struct User {
    #[cryptonamo(query = "blah")]
    email: String,
}

fn main() {}
