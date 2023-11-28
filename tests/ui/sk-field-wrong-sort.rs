use cryptonamo::Encryptable;

#[derive(Debug, Encryptable)]
struct User {
    #[cryptonamo(query = "exact", compound = "email#name")]
    #[partition_key]
    email: String,
    #[cryptonamo(query = "prefix", compound = "email#name")]
    #[sort_key]
    name: String,

    sk: String,
}

fn main() {}
