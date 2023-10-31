use cryptonamo::Cryptonamo;

#[derive(Debug, Cryptonamo)]
#[cryptonamo(partition_key = "email")]
struct User {
    #[cryptonamo(query = "exact", compound = "email#name")]
    email: String,
    #[cryptonamo(query = "prefix", compound = "email#name")]
    name: String,
}

fn main() {}
