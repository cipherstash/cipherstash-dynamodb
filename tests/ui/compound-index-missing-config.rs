use cryptonamo::Cryptonamo;

#[derive(Cryptonamo)]
#[cryptonamo(partition_key = "email")]
struct User {
    #[cryptonamo(compound = "email#name")]
    email: String,
    #[cryptonamo(compound = "email#name")]
    name: String,
}

fn main() {}
