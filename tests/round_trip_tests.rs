use cryptonamo::{Decryptable, Encryptable, EncryptedTable, Searchable};

mod common;

#[derive(Debug, Clone, PartialEq, Encryptable, Decryptable, Searchable)]
struct Crazy {
    #[partition_key]
    email: String,

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

#[tokio::test]
async fn test_round_trip() {
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
    };

    table.put(r.clone()).await.expect("Failed to insert record");

    let s: Crazy = table
        .get(("dan@coderdan.co", "Dan"))
        .await
        .expect("Failed to get record")
        .unwrap();

    assert_eq!(s, r);
}
