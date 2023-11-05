use cryptonamo::Encryptable;

#[derive(Encryptable)]
struct User {
    #[cryptonamo(query = "exact", compound = "email#name")]
    email: String,
    #[cryptonamo(query = "exact", compound = "email#name")]
    name: String,
    #[cryptonamo(query = "exact", compound = "email#name")]
    age: usize,
}

fn main() {}
