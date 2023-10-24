use std::marker::PhantomData;

use crate::{crypto::*, table_entry::TableEntry, DecryptedRecord, EncryptedRecord};
use aws_sdk_dynamodb::{
    types::{AttributeValue, Put, TransactWriteItem},
    Client,
};
use cipherstash_client::{
    config::{console_config::ConsoleConfig, errors::ConfigError, vitur_config::ViturConfig},
    credentials::{auto_refresh::AutoRefresh, vitur_credentials::ViturCredentials},
    encryption::{
        compound_indexer::{ComposableIndex, ComposablePlaintext, CompoundIndex, Operator},
        Encryption, EncryptionError, IndexTerm, Plaintext,
    },
    vitur::{errors::LoadConfigError, DatasetConfigWithIndexRootKey, Vitur},
};
use itertools::Itertools;
use log::info;
use serde_dynamo::{aws_sdk_dynamodb_0_29::from_item, from_items, to_item};
use thiserror::Error;

pub struct EncryptedTable {
    db: Client,
    cipher: Box<Encryption<AutoRefresh<ViturCredentials>>>,
    dataset_config: DatasetConfigWithIndexRootKey,
    table_name: String,
}

pub struct Query<T> {
    parts: Vec<(String, Plaintext, Operator)>,
    __table: PhantomData<T>,
}

#[derive(Error, Debug)]
pub enum QueryError {
    #[error("InvaldQuery: {0}")]
    InvalidQuery(String),
    #[error("EncryptionError: {0}")]
    EncryptionError(#[from] EncryptionError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("SerdeError: {0}")]
    SerdeError(#[from] serde_dynamo::Error),
    #[error("AwsError: {0}")]
    AwsError(String),
    #[error("{0}")]
    Other(String),
}

#[derive(Error, Debug)]
pub enum PutError {
    #[error("AwsError: {0}")]
    AwsError(String),
    #[error("SerdeError: {0}")]
    SerdeError(#[from] serde_dynamo::Error),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
}

#[derive(Error, Debug)]
pub enum GetError {
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("AwsError: {0}")]
    AwsError(String),
}

#[derive(Error, Debug)]
pub enum InitError {
    #[error("ConfigError: {0}")]
    ConfigError(#[from] ConfigError),
    #[error("LoadConfigError: {0}")]
    LoadConfigError(#[from] LoadConfigError),
}

impl<T: EncryptedRecord> Query<T> {
    pub fn eq(name: impl Into<String>, plaintext: impl Into<Plaintext>) -> Self {
        Self::new(name.into(), plaintext.into(), Operator::Eq)
    }

    pub fn starts_with(name: impl Into<String>, plaintext: impl Into<Plaintext>) -> Self {
        Self::new(name.into(), plaintext.into(), Operator::StartsWith)
    }

    pub fn new(name: String, plaintext: Plaintext, op: Operator) -> Self {
        Self {
            parts: vec![(name, plaintext, op)],
            __table: Default::default(),
        }
    }

    pub fn and_eq(mut self, name: impl Into<String>, plaintext: impl Into<Plaintext>) -> Self {
        self.parts.push((name.into(), plaintext.into(), Operator::Eq));
        self
    }

    pub fn and_starts_with(mut self, name: impl Into<String>, plaintext: impl Into<Plaintext>) -> Self {
        self.parts.push((name.into(), plaintext.into(), Operator::StartsWith));
        self
    }

    pub fn build(
        self,
    ) -> Result<(String, Box<dyn ComposableIndex>, ComposablePlaintext), QueryError> {
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

                return Ok((name, index, plaintext));
            }
        }

        let fields = self.parts.iter().map(|x| &x.0).join(",");

        Err(QueryError::InvalidQuery(format!(
            "Could not build query for fields: {fields}"
        )))
    }
}

impl EncryptedTable {
    pub async fn init(
        db: Client,
        table_name: impl Into<String>,
    ) -> Result<EncryptedTable, InitError> {
        info!("Initializing...");
        let console_config = ConsoleConfig::builder().with_env().build()?;
        let vitur_config = ViturConfig::builder()
            .decryption_log(true)
            .with_env()
            .console_config(&console_config)
            .build_with_client_key()?;

        let vitur_client = Vitur::new_with_client_key(
            &vitur_config.base_url(),
            AutoRefresh::new(vitur_config.credentials()),
            vitur_config.decryption_log_path().as_deref(),
            vitur_config.client_key(),
        );

        info!("Fetching dataset config...");
        let dataset_config = vitur_client.load_dataset_config().await?;
        let cipher = Box::new(Encryption::new(dataset_config.index_root_key, vitur_client));

        info!("Ready!");

        Ok(Self {
            db,
            cipher,
            dataset_config,
            table_name: table_name.into(),
        })
    }

    pub async fn query<R, Q>(self, query: Query<Q>) -> Result<Vec<R>, QueryError>
    where
        Q: EncryptedRecord,
        R: DecryptedRecord,
    {
        let (index_name, index, plaintext) = query.build()?;

        let index_term = self.cipher.compound_query(
            &CompoundIndex::new(index),
            plaintext,
            Some(format!("{}#{}", R::type_name(), index_name)),
            12,
        )?;

        // With DynamoDB queries must always return a single term
        let term = if let IndexTerm::Binary(x) = index_term {
            hex::encode(x)
        } else {
            Err(QueryError::Other(format!(
                "Returned IndexTerm had invalid type: {index_term:?}"
            )))?
        };

        let query = self
            .db
            .query()
            .table_name(&self.table_name)
            .index_name("TermIndex")
            .key_condition_expression("term = :term")
            .expression_attribute_values(":term", AttributeValue::S(term));

        let result = query
            .send()
            .await
            .map_err(|e| QueryError::AwsError(e.to_string()))?;

        let items = result
            .items
            .ok_or_else(|| QueryError::AwsError("Expected items entry on aws response".into()))?;

        let table_entries: Vec<TableEntry> = from_items(items)?;

        let mut results: Vec<R> = Vec::with_capacity(table_entries.len());

        // TODO: Bulk Decrypt
        for te in table_entries.into_iter() {
            let attributes = decrypt(te.attributes, &self.cipher).await?;
            let record: R = R::from_attributes(attributes);
            results.push(record);
        }

        Ok(results)
    }

    pub async fn get<T>(&self, pk: &str) -> Result<Option<T>, GetError>
    where
        T: EncryptedRecord + DecryptedRecord,
    {
        let pk = encrypt_partition_key(pk, &self.cipher)?;

        let result = self
            .db
            .get_item()
            .table_name(&self.table_name)
            .key("pk", AttributeValue::S(pk))
            .key("sk", AttributeValue::S(T::type_name().to_string()))
            .send()
            .await
            .map_err(|e| GetError::AwsError(e.to_string()))?;

        let table_entry: Option<TableEntry> = result
            .item
            .map(|item| from_item(item).map_err(|e| GetError::AwsError(e.to_string())))
            .transpose()?;

        if let Some(TableEntry { attributes, .. }) = table_entry {
            let attributes = decrypt(attributes, &self.cipher).await?;
            Ok(Some(T::from_attributes(attributes)))
        } else {
            Ok(None)
        }
    }

    pub async fn put<T>(&self, record: &T) -> Result<(), PutError>
    where
        T: EncryptedRecord,
    {
        let table_config = self
            .dataset_config
            .config
            .get_table(&T::type_name())
            .expect(&format!("No config found for type {:?}", record));

        // TODO: Use a combinator
        let table_entries = encrypt(record, &self.cipher, table_config).await?;
        let mut items: Vec<TransactWriteItem> = Vec::with_capacity(table_entries.len());
        for entry in table_entries.into_iter() {
            let item = Some(to_item(entry)?);

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
            .map_err(|e| PutError::AwsError(e.to_string()))?;

        Ok(())
    }
}
