use cryptonamo::Encryptable;

#[derive(Encryptable)]
struct User {
    email: String,
    #[cryptonamo(query = "exact", compound = "email#name")]
    name: String,
}

fn main() {}
