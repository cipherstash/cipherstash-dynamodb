use cryptonamo::Encryptable;

#[derive(Debug, Encryptable)]
struct Crazy {
    #[cryptonamo(query = "exact", compound = "email#name")]
    #[partition_key]
    email: String,

    #[cryptonamo(query = "prefix", compound = "email#name")]
    #[sort_key]
    name: String,

    #[cryptonamo(query = "exact")]
    ct_a: i64,
    #[cryptonamo(query = "exact")]
    ct_b: i32,
    #[cryptonamo(query = "exact")]
    ct_c: i16,
    #[cryptonamo(query = "exact")]
    ct_d: f64,
    #[cryptonamo(query = "exact")]
    ct_e: bool,
    #[cryptonamo(query = "exact")]
    ct_h: u64,

    #[cryptonamo(plaintext)]
    pt_a: i64,
    #[cryptonamo(plaintext)]
    pt_b: i32,
    #[cryptonamo(plaintext)]
    pt_c: i16,
    #[cryptonamo(plaintext)]
    pt_d: f64,
    #[cryptonamo(plaintext)]
    pt_e: bool,
    #[cryptonamo(plaintext)]
    pt_f: u64,
    #[cryptonamo(plaintext)]
    pt_g: u32,
    #[cryptonamo(plaintext)]
    pt_h: u16,
    #[cryptonamo(plaintext)]
    pt_i: Vec<u8>,
    #[cryptonamo(plaintext)]
    pt_j: Vec<String>,
    #[cryptonamo(plaintext)]
    pt_k: Vec<Vec<u8>>,
}

fn main() {}
