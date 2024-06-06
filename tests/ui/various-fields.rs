use cipherstash_dynamodb::Encryptable;

#[derive(Debug, Encryptable)]
struct Crazy {
    #[cipherstash(query = "exact", compound = "email#name")]
    #[partition_key]
    email: String,

    #[cipherstash(query = "prefix", compound = "email#name")]
    #[sort_key]
    name: String,

    #[cipherstash(query = "exact")]
    ct_str_a: String,
    #[cipherstash(query = "exact")]
    ct_str_b: Option<String>,
    #[cipherstash(query = "exact")]
    ct_str_c: Option<&'static str>,
    #[cipherstash(query = "exact")]
    ct_str_d: &'static str,

    #[cipherstash(query = "exact")]
    ct_a: i64,
    #[cipherstash(query = "exact")]
    ct_b: i32,
    #[cipherstash(query = "exact")]
    ct_c: i16,
    #[cipherstash(query = "exact")]
    ct_d: f64,
    #[cipherstash(query = "exact")]
    ct_e: bool,
    #[cipherstash(query = "exact")]
    ct_h: u64,

    #[cipherstash(query = "exact")]
    ct_option_a: Option<i64>,
    #[cipherstash(query = "exact")]
    ct_option_b: Option<i32>,
    #[cipherstash(query = "exact")]
    ct_option_c: Option<i16>,
    #[cipherstash(query = "exact")]
    ct_option_d: Option<f64>,
    #[cipherstash(query = "exact")]
    ct_option_e: Option<bool>,
    #[cipherstash(query = "exact")]
    ct_option_h: Option<u64>,

    #[cipherstash(plaintext)]
    pt_a: i64,
    #[cipherstash(plaintext)]
    pt_b: i32,
    #[cipherstash(plaintext)]
    pt_c: i16,
    #[cipherstash(plaintext)]
    pt_d: f64,
    #[cipherstash(plaintext)]
    pt_e: bool,
    #[cipherstash(plaintext)]
    pt_f: u64,
    #[cipherstash(plaintext)]
    pt_g: u32,
    #[cipherstash(plaintext)]
    pt_h: u16,
    #[cipherstash(plaintext)]
    pt_i: Vec<u8>,
    #[cipherstash(plaintext)]
    pt_j: Vec<String>,
    #[cipherstash(plaintext)]
    pt_k: Vec<Vec<u8>>,
    #[cipherstash(plaintext)]
    pt_l: String,

    #[cipherstash(plaintext)]
    pt_option_a: Option<i64>,
    #[cipherstash(plaintext)]
    pt_option_b: Option<i32>,
    #[cipherstash(plaintext)]
    pt_option_c: Option<i16>,
    #[cipherstash(plaintext)]
    pt_option_d: Option<f64>,
    #[cipherstash(plaintext)]
    pt_option_e: Option<bool>,
    #[cipherstash(plaintext)]
    pt_option_f: Option<u64>,
    #[cipherstash(plaintext)]
    pt_option_g: Option<u32>,
    #[cipherstash(plaintext)]
    pt_option_h: Option<u16>,
    #[cipherstash(plaintext)]
    pt_option_i: Option<Vec<u8>>,
    #[cipherstash(plaintext)]
    pt_option_j: Option<Vec<String>>,
    #[cipherstash(plaintext)]
    pt_option_k: Option<Vec<Vec<u8>>>,
    #[cipherstash(plaintext)]
    pt_option_l: String,
}

fn main() {}
