pub mod query;
pub use self::query::{Query, QueryBuilder, QueryError};
use crate::{crypto::*, table_entry::TableEntry, DecryptedRecord, EncryptedRecord};
use aws_sdk_dynamodb::{
    types::{AttributeValue, Put, TransactWriteItem},
    Client,
};
use cipherstash_client::{
    config::{console_config::ConsoleConfig, errors::ConfigError, vitur_config::ViturConfig},
    credentials::{auto_refresh::AutoRefresh, vitur_credentials::ViturCredentials},
    encryption::Encryption,
    vitur::{errors::LoadConfigError, DatasetConfigWithIndexRootKey, Vitur},
};
use log::info;
use serde_dynamo::{aws_sdk_dynamodb_0_29::from_item, to_item};
use thiserror::Error;

pub struct EncryptedTable {
    db: Client,
    cipher: Box<Encryption<AutoRefresh<ViturCredentials>>>,
    dataset_config: DatasetConfigWithIndexRootKey,
    table_name: String,
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

    pub fn query<R>(&self) -> QueryBuilder<R>
    where
        R: EncryptedRecord + DecryptedRecord,
    {
        QueryBuilder::new(&self)
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
