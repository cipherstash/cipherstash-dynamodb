mod common;

// TODO: Use the derive macros for this test
use cipherstash_client::encryption::TypeParseError;
use cipherstash_dynamodb::{
    crypto::Unsealed,
    errors::SealError,
    traits::{Plaintext, TryFromPlaintext, TryFromTableAttr},
    Decryptable, Encryptable, EncryptedTable, Identifiable, PkSk,
};
use cipherstash_dynamodb_derive::Searchable;
use miette::IntoDiagnostic;
use std::{borrow::Cow, collections::BTreeMap};

fn make_btree_map() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert("a".to_string(), "value-a".to_string());
    map.insert("b".to_string(), "value-b".to_string());
    map.insert("c".to_string(), "value-c".to_string());
    map
}

#[derive(Debug, Clone, PartialEq, Searchable)]
struct Test {
    #[partition_key]
    pub pk: String,
    #[sort_key]
    pub sk: String,
    pub name: String,
    pub age: i16,
    pub tag: String,
    pub attrs: BTreeMap<String, String>,
}

impl Identifiable for Test {
    type PrimaryKey = PkSk;

    fn get_primary_key(&self) -> Self::PrimaryKey {
        PkSk(self.pk.to_string(), self.sk.to_string())
    }
    #[inline]
    fn type_name() -> Cow<'static, str> {
        std::borrow::Cow::Borrowed("test")
    }
    #[inline]
    fn sort_key_prefix() -> Option<Cow<'static, str>> {
        None
    }
    fn is_pk_encrypted() -> bool {
        false
    }
    fn is_sk_encrypted() -> bool {
        false
    }
}

fn put_attrs(unsealed: &mut Unsealed, attrs: BTreeMap<String, String>) {
    attrs.into_iter().for_each(|(k, v)| {
        unsealed.add_protected_map_field("attrs", k, Plaintext::from(v));
    })
}

impl Encryptable for Test {
    fn protected_attributes() -> Cow<'static, [Cow<'static, str>]> {
        Cow::Borrowed(&[
            Cow::Borrowed("name"),
            Cow::Borrowed("age"),
            Cow::Borrowed("attrs"),
        ])
    }

    fn plaintext_attributes() -> Cow<'static, [Cow<'static, str>]> {
        Cow::Borrowed(&[
            Cow::Borrowed("tag"),
            Cow::Borrowed("pk"),
            Cow::Borrowed("sk"),
        ])
    }

    fn into_unsealed(self) -> Unsealed {
        let mut unsealed = Unsealed::new_with_descriptor(<Self as Identifiable>::type_name());
        unsealed.add_unprotected("pk", self.pk);
        unsealed.add_unprotected("sk", self.sk);
        unsealed.add_protected("name", self.name);
        unsealed.add_protected("age", self.age);
        unsealed.add_unprotected("tag", self.tag);
        put_attrs(&mut unsealed, self.attrs);
        println!("Encryption: {:?}", unsealed);
        unsealed
    }
}

fn get_attrs<T>(unsealed: &mut Unsealed) -> Result<T, TypeParseError>
where
    T: FromIterator<(String, String)>,
{
    unsealed
        .take_protected_map("attrs")
        .ok_or(TypeParseError("attrs".to_string()))?
        .into_iter()
        .map(|(k, v)| TryFromPlaintext::try_from_plaintext(v).map(|v| (k, v)))
        .collect()
}

impl Decryptable for Test {
    fn from_unsealed(mut unsealed: Unsealed) -> Result<Self, SealError> {
        println!("{:?}", unsealed);
        Ok(Self {
            pk: TryFromTableAttr::try_from_table_attr(unsealed.get_plaintext("pk"))?,
            sk: TryFromTableAttr::try_from_table_attr(unsealed.get_plaintext("sk"))?,
            name: TryFromPlaintext::try_from_optional_plaintext(unsealed.take_protected("name"))?,
            age: TryFromPlaintext::try_from_optional_plaintext(unsealed.take_protected("age"))?,
            tag: TryFromTableAttr::try_from_table_attr(unsealed.get_plaintext("tag"))?,
            attrs: get_attrs(&mut unsealed)?,
        })
    }

    fn protected_attributes() -> Cow<'static, [Cow<'static, str>]> {
        Cow::Borrowed(&[
            Cow::Borrowed("name"),
            Cow::Borrowed("age"),
            Cow::Borrowed("attrs"),
        ])
    }

    fn plaintext_attributes() -> Cow<'static, [Cow<'static, str>]> {
        Cow::Borrowed(&[
            Cow::Borrowed("tag"),
            Cow::Borrowed("pk"),
            Cow::Borrowed("sk"),
        ])
    }
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
