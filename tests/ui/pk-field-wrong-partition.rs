use cryptonamo::Encryptable;

#[derive(Debug, Encryptable)]
struct User {
    #[partition_key]
    #[cryptonamo(query = "exact", compound = "email#name")]
    email: String,
    #[cryptonamo(query = "prefix", compound = "email#name")]
    name: String,

    pk: String,
}

fn main() {}
