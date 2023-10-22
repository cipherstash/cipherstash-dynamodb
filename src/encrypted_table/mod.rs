use crate::{
    crypto::*, table_entry::TableEntry, CompoundAttributeOrig, DecryptedRecord, EncryptedRecord,
};
use aws_sdk_dynamodb::{
    types::{AttributeValue, Put, TransactWriteItem},
    Client,
};
use cipherstash_client::{
    config::{console_config::ConsoleConfig, vitur_config::ViturConfig},
    credentials::{auto_refresh::AutoRefresh, vitur_credentials::ViturCredentials},
    encryption::{Encryption, Plaintext, compound_indexer::{ComposablePlaintext, Accumulator}},
    vitur::{DatasetConfigWithIndexRootKey, Vitur},
};
use log::info;
use serde_dynamo::{aws_sdk_dynamodb_0_29::from_item, from_items, to_item};

pub struct EncryptedTable {
    db: Client,
    cipher: Box<Encryption<AutoRefresh<ViturCredentials>>>,
    dataset_config: DatasetConfigWithIndexRootKey,
    table_name: String,
}

impl EncryptedTable {
    pub async fn init(db: Client, table_name: impl Into<String>) -> EncryptedTable {
        info!("Initializing...");
        let console_config = ConsoleConfig::builder().with_env().build().unwrap();
        let vitur_config = ViturConfig::builder()
            .decryption_log(true)
            .with_env()
            .console_config(&console_config)
            .build_with_client_key()
            .unwrap();

        let vitur_client = Vitur::new_with_client_key(
            &vitur_config.base_url(),
            AutoRefresh::new(vitur_config.credentials()),
            vitur_config.decryption_log_path().as_deref(),
            vitur_config.client_key(),
        );

        info!("Fetching dataset config...");
        let dataset_config = vitur_client.load_dataset_config().await.unwrap();
        let cipher = Box::new(Encryption::new(dataset_config.index_root_key, vitur_client));

        info!("Ready!");

        Self {
            db,
            cipher,
            dataset_config,
            table_name: table_name.into(),
        }
    }

    pub async fn query<R, Q>(
        self,
        query: Q
    ) -> Vec<R>
    where
    R: DecryptedRecord + EncryptedRecord, // FIXME: This be DecryptedRecord + QueryableRecord
    Q: Into<ComposablePlaintext>
    {
        let query: ComposablePlaintext = query.into();

        let key = [0; 32]; // FIXME: pass the cipher and use the key from there
        let terms = R::index_by_name("email#name")
            .expect("No index defined")
            .compose_index(key, query, Accumulator::from_salt("email#name")).unwrap() // FIXME
            .truncate(12) // TODO: Make this configurable (maybe on E?)
            .terms();

        for t in terms.iter() {
            dbg!(hex::encode(t));
        }

        // FIXME: Using the last term is inefficient. We probably should have a compose_query method on composable index
        let term = hex::encode(terms.last().unwrap());

        let query = self
            .db
            .query()
            .table_name(&self.table_name)
            .index_name("TermIndex")
            .key_condition_expression("term = :term")
            .expression_attribute_values(":term", AttributeValue::S(term));

        let result = query.send().await.unwrap();
        let table_entries: Vec<TableEntry> = from_items(result.items.unwrap()).unwrap();
        let mut results: Vec<R> = Vec::with_capacity(table_entries.len());

        // TODO: Bulk Decrypt
        for te in table_entries.into_iter() {
            let attributes = decrypt(te.attributes, &self.cipher).await;
            let record: R = R::from_attributes(attributes);
            results.push(record);
        }

        results
    }

    // TODO: This can be replaced with the query above
    pub async fn query_match_exact<R: DecryptedRecord>(
        self,
        left: (&str, &str),
        right: (&str, &Plaintext),
    ) -> Vec<R> {
        let table_config = self
            .dataset_config
            .config
            .get_table(&R::type_name())
            .expect("No config found for type");

        let query = (
            &Plaintext::Utf8Str(Some(left.1.to_string())),
            right.1,
            &CompoundAttributeOrig::BeginsWith(left.0.to_string(), right.0.to_string()),
        );

        let term = encrypt_composite_query(R::type_name(), query, table_config, &self.cipher)
            .expect("Failed to encrypt query");

        let query = self
            .db
            .query()
            .table_name(&self.table_name)
            .index_name("TermIndex")
            .key_condition_expression("term = :term")
            .expression_attribute_values(":term", AttributeValue::S(term));

        let result = query.send().await.unwrap();

        let table_entries: Vec<TableEntry> = from_items(result.items.unwrap()).unwrap();

        let mut results: Vec<R> = Vec::with_capacity(table_entries.len());

        // TODO: Bulk Decrypt
        for te in table_entries.into_iter() {
            let attributes = decrypt(te.attributes, &self.cipher).await;
            let record: R = R::from_attributes(attributes);
            results.push(record);
        }

        results
    }

    pub async fn get<T>(&self, pk: &str) -> Option<T>
    where
        T: EncryptedRecord + DecryptedRecord,
    {
        let pk = encrypt_partition_key(pk, &self.cipher).unwrap();

        let result = self
            .db
            .get_item()
            .table_name(&self.table_name)
            .key("pk", AttributeValue::S(pk))
            .key("sk", AttributeValue::S(T::type_name().to_string()))
            .send()
            .await
            .unwrap();
        let table_entry: Option<TableEntry> = result.item.and_then(|item| from_item(item).unwrap());

        if let Some(TableEntry { attributes, .. }) = table_entry {
            let attributes = decrypt(attributes, &self.cipher).await;
            Some(T::from_attributes(attributes))
        } else {
            None
        }
    }

    pub async fn put<T>(&self, record: &T)
    where
        T: EncryptedRecord,
    {
        let table_config = self
            .dataset_config
            .config
            .get_table(&T::type_name())
            .expect(&format!("No config found for type {:?}", record));

        // TODO: Use a combinator
        let table_entries = encrypt(record, &self.cipher, table_config).await.unwrap();
        let mut items: Vec<TransactWriteItem> = Vec::with_capacity(table_entries.len());
        for entry in table_entries.into_iter() {
            let item = Some(to_item(entry).unwrap());

            println!("ITEM: {item:#?}");

            items.push(
                TransactWriteItem::builder()
                    .put(
                        Put::builder()
                            .table_name(&self.table_name)
                            .set_item(item)
                            .build(),
                    )
                    .build(),
            );
        }

        dbg!(&items);

        self.db
            .transact_write_items()
            .set_transact_items(Some(items))
            .send()
            .await
            .unwrap(); // FIXME
    }
}
