use crate::{
    crypto::*, dict::DynamoDict, table_entry::TableEntry, DecryptedRecord, EncryptedRecord,
};
use aws_sdk_dynamodb::{
    types::{AttributeValue, Put, TransactWriteItem},
    Client,
};
use cipherstash_client::{
    config::{console_config::ConsoleConfig, vitur_config::ViturConfig},
    credentials::{auto_refresh::AutoRefresh, vitur_credentials::ViturCredentials},
    encryption::Encryption,
    vitur::{DatasetConfigWithIndexRootKey, Vitur},
};
use log::info;
use serde_dynamo::{aws_sdk_dynamodb_0_29::from_item, from_items, to_item};

pub struct EncryptedTable<'c> {
    db: &'c Client,
    cipher: Box<Encryption<AutoRefresh<ViturCredentials>>>,
    dataset_config: DatasetConfigWithIndexRootKey,
    dictionary: DynamoDict<'c>,
    table_name: String,
}

impl<'c> EncryptedTable<'c> {
    pub async fn init(db: &'c Client, table_name: impl Into<String>) -> EncryptedTable<'c> {
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

        // TODO: Keep the dictionary in an Arc and implement the trait for the Arc?
        let dictionary = DynamoDict::init(&db, dataset_config.index_root_key);

        info!("Ready!");

        Self {
            db,
            cipher,
            dictionary,
            dataset_config,
            table_name: table_name.into(),
        }
    }

    pub async fn query<R>(self, field_name: &str, query: &str) -> Vec<R>
    where
        R: DecryptedRecord,
    {
        let table_config = self
            .dataset_config
            .config
            .get_table(&R::type_name())
            .expect("No config found for type");

        let terms = encrypt_query(
            &query.to_string().into(),
            field_name,
            &self.cipher,
            table_config,
            &self.dictionary,
        )
        .await;

        let terms_list: String = terms
            .iter()
            .enumerate()
            .map(|(i, _)| format!(":t{i}"))
            .collect::<Vec<String>>()
            .join(",");

        let mut query = self
            .db
            .query()
            .table_name(&self.table_name)
            .index_name("TermIndex")
            .key_condition_expression("field = :field")
            .expression_attribute_values(":field", AttributeValue::S(field_name.to_string()))
            .filter_expression(format!("term in ({terms_list})"));

        for (i, term) in terms.into_iter().enumerate() {
            query = query.expression_attribute_values(format!(":t{i}"), AttributeValue::S(term));
        }

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
        let pk = encrypt_partition_key(T::type_name(), pk, &self.cipher);
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
        let table_entries = encrypt(record, &self.cipher, table_config, &self.dictionary).await;
        let mut items: Vec<TransactWriteItem> = Vec::with_capacity(table_entries.len());
        for entry in table_entries.into_iter() {
            items.push(
                TransactWriteItem::builder()
                    .put(
                        Put::builder()
                            .table_name(&self.table_name)
                            .set_item(Some(to_item(entry).unwrap()))
                            .build(),
                    )
                    .build(),
            );
        }

        self.db
            .transact_write_items()
            .set_transact_items(Some(items))
            .send()
            .await
            .unwrap();
    }
}
