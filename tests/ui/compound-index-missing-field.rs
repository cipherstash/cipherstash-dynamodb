use cryptonamo::Cryptonamo;

#[derive(Cryptonamo)]
struct User {
    email: String,
    #[cryptonamo(query = "exact", compound = "email#name")]
    name: String,
}

fn main() {}
