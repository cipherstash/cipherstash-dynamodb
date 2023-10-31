use cryptonamo::Cryptonamo;

#[derive(Debug, Cryptonamo)]
#[cryptonamo(partition_key = "email")]
struct User {
    #[cryptonamo(query = "prefix", compound = "email#name")]
    email: String,
    #[cryptonamo(query = "blah", compound = "email#name")]
    name: String,
}

fn main() {}
