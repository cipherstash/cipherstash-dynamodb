use cipherstash_dynamodb::{Decryptable, Encryptable, EncryptedTable, Identifiable, Searchable};
use miette::IntoDiagnostic;
mod common;

#[derive(Debug, Clone, PartialEq, Identifiable, Encryptable, Decryptable, Searchable)]
struct Crazy {
    #[partition_key]
    email: String,

    #[sort_key]
    name: String,

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
    ct_a_some: Option<i64>,
    #[cipherstash(query = "exact")]
    ct_b_some: Option<i32>,
    #[cipherstash(query = "exact")]
    ct_c_some: Option<i16>,
    #[cipherstash(query = "exact")]
    ct_d_some: Option<f64>,
    #[cipherstash(query = "exact")]
    ct_e_some: Option<bool>,
    #[cipherstash(query = "exact")]
    ct_h_some: Option<u64>,
    #[cipherstash(query = "exact")]
    ct_i_some: Option<String>,

    #[cipherstash(query = "exact")]
    ct_a_none: Option<i64>,
    #[cipherstash(query = "exact")]
    ct_b_none: Option<i32>,
    #[cipherstash(query = "exact")]
    ct_c_none: Option<i16>,
    #[cipherstash(query = "exact")]
    ct_d_none: Option<f64>,
    #[cipherstash(query = "exact")]
    ct_e_none: Option<bool>,
    #[cipherstash(query = "exact")]
    ct_h_none: Option<u64>,
    #[cipherstash(query = "exact")]
    ct_i_none: Option<String>,

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
    pt_a_some: Option<i64>,
    #[cipherstash(plaintext)]
    pt_b_some: Option<i32>,
    #[cipherstash(plaintext)]
    pt_c_some: Option<i16>,
    #[cipherstash(plaintext)]
    pt_d_some: Option<f64>,
    #[cipherstash(plaintext)]
    pt_e_some: Option<bool>,
    #[cipherstash(plaintext)]
    pt_f_some: Option<u64>,
    #[cipherstash(plaintext)]
    pt_g_some: Option<u32>,
    #[cipherstash(plaintext)]
    pt_h_some: Option<u16>,
    #[cipherstash(plaintext)]
    pt_i_some: Option<Vec<u8>>,
    #[cipherstash(plaintext)]
    pt_j_some: Option<Vec<String>>,
    #[cipherstash(plaintext)]
    pt_k_some: Option<Vec<Vec<u8>>>,

    #[cipherstash(plaintext)]
    pt_a_none: Option<i64>,
    #[cipherstash(plaintext)]
    pt_b_none: Option<i32>,
    #[cipherstash(plaintext)]
    pt_c_none: Option<i16>,
    #[cipherstash(plaintext)]
    pt_d_none: Option<f64>,
    #[cipherstash(plaintext)]
    pt_e_none: Option<bool>,
    #[cipherstash(plaintext)]
    pt_f_none: Option<u64>,
    #[cipherstash(plaintext)]
    pt_g_none: Option<u32>,
    #[cipherstash(plaintext)]
    pt_h_none: Option<u16>,
    #[cipherstash(plaintext)]
    pt_i_none: Option<Vec<u8>>,
    #[cipherstash(plaintext)]
    pt_j_none: Option<Vec<String>>,
    #[cipherstash(plaintext)]
    pt_k_none: Option<Vec<Vec<u8>>>,
}

#[tokio::test]
async fn test_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let config = aws_config::from_env()
        .endpoint_url("http://localhost:8000")
        .load()
        .await;

    let client = aws_sdk_dynamodb::Client::new(&config);

    let table_name = "crazy-record";

    common::create_table(&client, table_name).await;

    let table = EncryptedTable::init(client, table_name)
        .await
        .expect("Failed to init table");

    let r = Crazy {
        email: "dan@coderdan.co".into(),
        name: "Dan".into(),

        ct_a: 123,
        ct_b: 321,
        ct_c: 231,
        ct_d: 20.20,
        ct_e: true,
        ct_h: 1200,

        ct_a_some: Some(123),
        ct_b_some: Some(321),
        ct_c_some: Some(231),
        ct_d_some: Some(20.20),
        ct_e_some: Some(true),
        ct_h_some: Some(1200),
        ct_i_some: Some("hello".to_string()),

        ct_a_none: None,
        ct_b_none: None,
        ct_c_none: None,
        ct_d_none: None,
        ct_e_none: None,
        ct_h_none: None,
        ct_i_none: None,

        pt_a: 1234,
        pt_b: 4321,
        pt_c: 3241,
        pt_d: 30.30,
        pt_e: false,
        pt_f: 2400,
        pt_g: 2300,
        pt_h: 2200,

        pt_i: vec![1, 2, 3, 4, 5],
        pt_j: vec!["Hey".into(), "There".into()],
        pt_k: vec![vec![1, 2, 3]],

        pt_a_some: Some(1234),
        pt_b_some: Some(4321),
        pt_c_some: Some(3241),
        pt_d_some: Some(30.30),
        pt_e_some: Some(false),
        pt_f_some: Some(2400),
        pt_g_some: Some(2300),
        pt_h_some: Some(2200),

        pt_i_some: Some(vec![1, 2, 3, 4, 5]),
        pt_j_some: Some(vec!["Hey".into(), "There".into()]),
        pt_k_some: Some(vec![vec![1, 2, 3]]),

        pt_a_none: None,
        pt_b_none: None,
        pt_c_none: None,
        pt_d_none: None,
        pt_e_none: None,
        pt_f_none: None,
        pt_g_none: None,
        pt_h_none: None,

        pt_i_none: None,
        pt_j_none: None,
        pt_k_none: None,
    };

    table.put(r.clone()).await.into_diagnostic()?;

    let s: Crazy = table
        .get(("dan@coderdan.co", "Dan"))
        .await
        .into_diagnostic()?
        .unwrap();

    assert_eq!(s, r);

    Ok(())
}
