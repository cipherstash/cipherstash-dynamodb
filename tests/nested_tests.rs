mod common;
use cipherstash_client::encryption::TypeParseError;
use cipherstash_dynamodb::{
    crypto::Unsealed,
    errors::SealError,
    traits::{Plaintext, TryFromPlaintext},
    Decryptable, Encryptable, EncryptedTable, Identifiable,
};
use cipherstash_dynamodb_derive::Searchable;
use miette::IntoDiagnostic;
use std::collections::BTreeMap;

fn make_btree_map() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert("a".to_string(), "value-a".to_string());
    map.insert("b".to_string(), "value-b".to_string());
    map.insert("c".to_string(), "value-c".to_string());
    map
}

#[derive(Debug, Clone, PartialEq, Searchable, Encryptable, Decryptable, Identifiable)]
struct Test {
    #[partition_key]
    pub pk: String,
    #[sort_key]
    pub sk: String,
    pub name: String,
    pub age: i16,
    #[cipherstash(plaintext)]
    pub tag: String,
    #[cipherstash(encryptable_with = put_attrs, decryptable_with = get_attrs)]
    pub attrs: BTreeMap<String, String>,
}

fn put_attrs(unsealed: &mut Unsealed, attrs: BTreeMap<String, String>) {
    attrs.into_iter().for_each(|(k, v)| {
        unsealed.add_protected_map_field("attrs", k, Plaintext::from(v));
    })
}

fn get_attrs<T>(unsealed: &mut Unsealed) -> Result<T, SealError>
where
    T: FromIterator<(String, String)>,
{
    unsealed
        .take_protected_map("attrs")
        .ok_or(TypeParseError("attrs".to_string()))?
        .into_iter()
        .map(|(k, v)| {
            TryFromPlaintext::try_from_plaintext(v)
                .map(|v| (k, v))
                .map_err(SealError::from)
        })
        .collect()
}

#[tokio::test]
async fn test_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let config = aws_config::from_env()
        .endpoint_url("http://localhost:8000")
        .load()
        .await;

    let client = aws_sdk_dynamodb::Client::new(&config);
    let table_name = "nested-record";

    common::create_table(&client, table_name).await;

    let table = EncryptedTable::init(client, table_name)
        .await
        .into_diagnostic()?;

    let record = Test {
        pk: "pk".to_string(),
        sk: "sk".to_string(),
        name: "name".to_string(),
        age: 42,
        tag: "tag".to_string(),
        attrs: make_btree_map(),
    };

    table.put(record.clone()).await.into_diagnostic()?;

    let check = table.get::<Test>(("pk", "sk")).await.into_diagnostic()?;

    assert_eq!(check, Some(record));

    Ok(())
}
