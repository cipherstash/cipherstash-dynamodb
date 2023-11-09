use cryptonamo::Encryptable;

#[derive(Debug, Encryptable)]
struct User {
    #[cryptonamo(query = "exact", compound = "email#name")]
    #[partition_key]
    email: String,
    #[cryptonamo(query = "prefix", compound = "email#name")]
    name: String,
}

fn main() {}
