mod common;

// TODO: Use the derive macros for this test
use std::{borrow::Cow, collections::BTreeMap};
use tracing_test::traced_test;

use cipherstash_client::encryption::TypeParseError;
use cipherstash_dynamodb::{
    crypto::Unsealed,
    errors::SealError,
    traits::{Plaintext, TableAttribute, TryFromPlaintext, TryFromTableAttr},
    Decryptable, Encryptable, EncryptedTable, Identifiable, PkSk,
};
use cipherstash_dynamodb_derive::Searchable;

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
        true
    }
    fn is_sk_encrypted() -> bool {
        false
    }
}

// TODO: Make this function consume and return the Unsealed
fn put_attrs(unsealed: &mut Unsealed, attrs: BTreeMap<String, String>) {
    attrs.into_iter().for_each(|(k, v)| {
        unsealed.add_protected(format!("attrs.{k}"), Plaintext::from(v));
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
        Cow::Borrowed(&[Cow::Borrowed("tag")])
    }

    fn into_unsealed(self) -> Unsealed {
        // FIXME: This should be a "consuming" method
        let mut unsealed = Unsealed::new_with_descriptor(<Self as Identifiable>::type_name());
        unsealed.add_protected("pk", Plaintext::from(self.pk));
        unsealed.add_unprotected("sk", TableAttribute::from(self.sk));
        unsealed.add_protected("name", Plaintext::from(self.name));
        unsealed.add_protected("age", Plaintext::from(self.age));
        unsealed.add_unprotected("tag", TableAttribute::from(self.tag));
        put_attrs(&mut unsealed, self.attrs);
        unsealed
    }
}

fn get_attrs<T>(unsealed: &Unsealed) -> Result<T, TypeParseError>
where
    T: FromIterator<(String, String)>,
{
    unsealed
        .nested_protected("attrs")
        .map(|(k, v)| TryFromPlaintext::try_from_plaintext(v).map(|v| (k, v)))
        .collect()
}

impl Decryptable for Test {
    fn from_unsealed(unsealed: Unsealed) -> Result<Self, SealError> {
        println!("IN FROM UNSEALED");
        Ok(Self {
            /*pk: TryFromTableAttr::try_from_table_attr(
                unsealed.get_plaintext("pk"),
            )?,
            sk: TryFromTableAttr::try_from_table_attr(
                unsealed.get_plaintext("sk"),
            )?,*/
            pk: String::from("pk-hack"),
            sk: String::from("sk-hack"),
            name: dbg!(TryFromPlaintext::try_from_optional_plaintext(
                dbg!(unsealed.get_protected("name")).cloned(),
            ))?,
            age: dbg!(TryFromPlaintext::try_from_optional_plaintext(
                unsealed.get_protected("age").cloned(),
            ))?,
            tag: dbg!(TryFromTableAttr::try_from_table_attr(
                unsealed.get_plaintext("tag"),
            ))?,
            attrs: dbg!(get_attrs(&unsealed))?,
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
        Cow::Borrowed(&[Cow::Borrowed("tag")])
    }
}

#[tokio::test]
#[traced_test]
async fn test_round_trip() {
    let config = aws_config::from_env()
        .endpoint_url("http://localhost:8000")
        .load()
        .await;

    let client = aws_sdk_dynamodb::Client::new(&config);
    let table_name = "nested-record";

    common::create_table(&client, table_name).await;

    let table = EncryptedTable::init(client, table_name)
        .await
        .expect("Failed to init table");

    let record = Test {
        pk: "pk".to_string(),
        sk: "sk".to_string(),
        name: "name".to_string(),
        age: 42,
        tag: "tag".to_string(),
        attrs: make_btree_map(),
    };

    table
        .put(record.clone())
        .await
        .expect("Failed to insert record");

    /*let check = table
        .get::<Test>(("pk", "sk"))
        .await;

    if let Err(e) = check {
        panic!("Failed to get record: {:?}", e);
    }*/

    assert!(false);

    //assert_eq!(check, record);
}
