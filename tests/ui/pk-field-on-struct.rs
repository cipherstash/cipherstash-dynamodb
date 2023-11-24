use cryptonamo::Encryptable;

#[derive(Debug, Encryptable)]
struct User {
    #[partition_key]
    pk: String,
    #[cryptonamo(query = "exact", compound = "email#name")]
    email: String,
    #[cryptonamo(query = "prefix", compound = "email#name")]
    name: String,
}

fn main() {}
