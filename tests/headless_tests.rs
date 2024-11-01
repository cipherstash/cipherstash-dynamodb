use aws_sdk_dynamodb::Client;
use cipherstash_dynamodb::{
    encrypted_table::PreparedRecord, Decryptable, Encryptable, EncryptedTable, Identifiable,
    Searchable,
};
use serial_test::serial;
use std::future::Future;

mod common;

#[derive(
    Identifiable, Encryptable, Decryptable, Searchable, Debug, PartialEq, Ord, PartialOrd, Eq, Clone,
)]
#[cipherstash(sort_key_prefix = "user")]
pub struct User {
    #[cipherstash(query = "exact", compound = "email#name")]
    #[cipherstash(query = "exact")]
    #[partition_key]
    pub email: String,

    #[cipherstash(query = "prefix", compound = "email#name")]
    #[cipherstash(query = "prefix")]
    pub name: String,

    #[cipherstash(plaintext)]
    pub tag: String,
}

impl User {
    pub fn new(email: impl Into<String>, name: impl Into<String>, tag: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            email: email.into(),
            tag: tag.into(),
        }
    }
}

async fn run_test<F: Future<Output = ()>>(f: impl FnOnce(Client, String) -> F) {
    let config = aws_config::from_env()
        .endpoint_url("http://localhost:8000")
        .load()
        .await;

    let client = aws_sdk_dynamodb::Client::new(&config);

    let table_name = "test-users-headless";

    common::create_table(&client, table_name).await;

    f(client, table_name.to_string()).await;
}

#[tokio::test]
#[serial]
async fn test_headless_roundtrip() {
    run_test(|client, table_name| async move {
        let user = User::new("john@john.co", "john", "tag");

        let table = EncryptedTable::init_headless()
            .await
            .expect("failed to init table");

        let user_record =
            PreparedRecord::prepare_record(user.clone()).expect("failed to prepare record");

        let patch = table
            .create_put_patch(user_record, None, |_, _| true)
            .await
            .expect("failed to encrypt");

        let items = patch
            .into_transact_write_items(&table_name)
            .expect("failed to create write items");

        client
            .transact_write_items()
            .set_transact_items(Some(items))
            .send()
            .await
            .expect("failed to insert");

        let items = client
            .scan()
            .table_name(&table_name)
            .send()
            .await
            .expect("failed to scan table")
            .items
            .expect("expected items to be Some")
            .into_iter()
            // get every record except the ones for use in the index
            .filter(|x| !x.contains_key("term"));

        let decrypted: Vec<User> = table.decrypt_all(items).await.expect("failed to decrypt");

        assert_eq!(decrypted, [user]);
    })
    .await;
}
