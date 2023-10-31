use cryptonamo::Cryptonamo;

#[derive(Cryptonamo)]
struct User {
    #[cryptonamo(compound = "email#name")]
    email: String,
    #[cryptonamo(compound = "email#name")]
    name: String,
}

fn main() {}
