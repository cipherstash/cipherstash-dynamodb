use std::marker::PhantomData;

use crate::{crypto::*, table_entry::TableEntry, DecryptedRecord, EncryptedRecord};
use aws_sdk_dynamodb::{
    types::{AttributeValue, Put, TransactWriteItem},
    Client,
};
use cipherstash_client::{
    config::{console_config::ConsoleConfig, vitur_config::ViturConfig},
    credentials::{auto_refresh::AutoRefresh, vitur_credentials::ViturCredentials},
    encryption::{
        compound_indexer::{ComposableIndex, ComposablePlaintext, CompoundIndex},
        Encryption, IndexTerm, Plaintext,
    },
    vitur::{DatasetConfigWithIndexRootKey, Vitur},
};
use itertools::Itertools;
use log::info;
use serde_dynamo::{aws_sdk_dynamodb_0_29::from_item, from_items, to_item};

pub struct EncryptedTable {
    db: Client,
    cipher: Box<Encryption<AutoRefresh<ViturCredentials>>>,
    dataset_config: DatasetConfigWithIndexRootKey,
    table_name: String,
}

pub struct Query<T> {
    parts: Vec<(String, Plaintext)>,
    __table: PhantomData<T>,
}

impl<T: EncryptedRecord> Query<T> {
    pub fn new(name: impl Into<String>, plaintext: impl Into<Plaintext>) -> Self {
        Self {
            parts: vec![(name.into(), plaintext.into())],
            __table: Default::default(),
        }
    }

    pub fn and(mut self, name: impl Into<String>, plaintext: impl Into<Plaintext>) -> Self {
        self.parts.push((name.into(), plaintext.into()));
        self
    }

    pub fn build(self) -> Option<(String, Box<dyn ComposableIndex>, ComposablePlaintext)> {
        let items_len = self.parts.len();

        // this is the simplest way to brute force the index names but relies on some gross
        // stringly typing which doesn't feel good
        for perm in self.parts.iter().permutations(items_len) {
            let (name, plaintexts): (Vec<&String>, Vec<&Plaintext>) =
                perm.into_iter().map(|x| (&x.0, &x.1)).unzip();

            let name = name.iter().join("#");

            if let Some(index) = T::index_by_name(name.as_str()) {
                let mut plaintext = ComposablePlaintext::new(plaintexts[0].clone());

                for p in plaintexts[1..].into_iter() {
                    plaintext = plaintext
                        .try_compose((*p).clone())
                        .expect("Failed to compose");
                }

                return Some((name, index, plaintext));
            }
        }

        None
    }
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

    pub async fn query<R, Q>(self, query: Query<Q>) -> Vec<R>
    where
        Q: EncryptedRecord,
        R: DecryptedRecord,
    {
        let (index_name, index, plaintext) = query.build().expect("Invalid query");

        let index_term = self
            .cipher
            .compound_index(
                &CompoundIndex::new(index),
                plaintext,
                Some(format!("{}#{}", R::type_name(), index_name)),
                12,
            )
            .expect("Failed to index");

        // FIXME: Using the last term is inefficient. We probably should have a compose_query method on composable index
        // It also assumes that the last term is the longest edgegram (i.e. most relevant) but it might
        // not always be the most relevant term for future index types. Also no unwrap.
        let term = match index_term {
            IndexTerm::Binary(x) => hex::encode(x),
            IndexTerm::BinaryVec(x) => hex::encode(x.last().unwrap()),
            _ => panic!("Invalid index term"),
        };

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
