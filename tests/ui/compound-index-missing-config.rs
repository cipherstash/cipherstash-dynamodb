use cryptonamo::Encryptable;

#[derive(Encryptable)]
#[cryptonamo(partition_key = "email")]
struct User {
    #[cryptonamo(compound = "email#name")]
    email: String,
    #[cryptonamo(compound = "email#name")]
    name: String,
}

fn main() {}
