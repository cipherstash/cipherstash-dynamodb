pub mod query;
mod table_entry;
pub use self::{
    query::{QueryBuilder, QueryError},
    table_entry::{Sealed, TableAttribute, TableEntry, Unsealed},
};
use crate::{
    crypto::*,
    traits::{
        DecryptedRecord, EncryptedRecord, ReadConversionError, SearchableRecord,
        WriteConversionError,
    },
};
use aws_sdk_dynamodb::{
    types::{AttributeValue, Delete, Put, TransactWriteItem},
    Client,
};
use cipherstash_client::{
    config::{console_config::ConsoleConfig, errors::ConfigError, vitur_config::ViturConfig},
    credentials::{auto_refresh::AutoRefresh, vitur_credentials::ViturCredentials},
    encryption::Encryption,
    vitur::{errors::LoadConfigError, DatasetConfigWithIndexRootKey, Vitur},
};
use itertools::Itertools;
use log::info;
use std::collections::HashSet;
use thiserror::Error;

pub struct EncryptedTable {
    db: Client,
    cipher: Box<Encryption<AutoRefresh<ViturCredentials>>>,
    // We may use this later but for now the config is in code
    _dataset_config: DatasetConfigWithIndexRootKey,
    table_name: String,
}

#[derive(Error, Debug)]
pub enum PutError {
    #[error("AwsError: {0}")]
    AwsError(String),
    #[error("Write Conversion Error: {0}")]
    WriteConversionError(#[from] WriteConversionError),
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
    #[error("ReadConversionError: {0}")]
    ReadConversionError(#[from] ReadConversionError),
}

#[derive(Error, Debug)]
pub enum DeleteError {
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
            _dataset_config: dataset_config,
            table_name: table_name.into(),
        })
    }

    pub fn query<R>(&self) -> QueryBuilder<R>
    where
        R: SearchableRecord + DecryptedRecord,
    {
        QueryBuilder::new(self)
    }

    pub async fn get<T>(&self, pk: &str) -> Result<Option<T>, GetError>
    where
        T: EncryptedRecord + DecryptedRecord,
    {
        let pk = encrypt_partition_key(pk, &self.cipher)?;
        let sk = T::type_name().to_string();

        let result = self
            .db
            .get_item()
            .table_name(&self.table_name)
            .key("pk", AttributeValue::S(pk))
            .key("sk", AttributeValue::S(sk))
            .send()
            .await
            .map_err(|e| GetError::AwsError(e.to_string()))?;

        let table_entry: Option<Sealed<TableEntry>> = result
            .item
            .map(|item| Sealed::<TableEntry>::try_from(item))
            .transpose()?;

        if let Some(sealed) = table_entry {
            let unsealed = Unsealed::<T>::unseal(sealed, &self.cipher).await;
            Ok(Some(T::from_unsealed(unsealed)?))
        } else {
            Ok(None)
        }
    }

    pub async fn delete<E: SearchableRecord>(&self, pk: &str) -> Result<(), DeleteError> {
        let pk = AttributeValue::S(encrypt_partition_key(pk, &self.cipher)?);

        let sk_to_delete = [E::type_name().to_string()]
            .into_iter()
            .chain(all_index_keys::<E>().into_iter());

        let transact_items = sk_to_delete.map(|sk| {
            TransactWriteItem::builder()
                .delete(
                    Delete::builder()
                        .table_name(&self.table_name)
                        .key("pk", pk.clone())
                        .key("sk", AttributeValue::S(sk))
                        .build(),
                )
                .build()
        });

        // Dynamo has a limit of 100 items per transaction
        for items in transact_items.chunks(100).into_iter() {
            self.db
                .transact_write_items()
                .set_transact_items(Some(items.collect()))
                .send()
                .await
                .map_err(|e| DeleteError::AwsError(e.to_string()))?;
        }

        Ok(())
    }

    pub async fn put<T>(&self, record: T) -> Result<(), PutError>
    where
        T: SearchableRecord,
    {
        let mut seen_sk = HashSet::new();

        let unsealed: Unsealed<T> = record.into_unsealed()?;
        let (pk, sealed) = unsealed.seal(&self.cipher, 12).await;

        // TODO: Use a combinator
        //let (pk, table_entries) = encrypt(record, &self.cipher).await?;
        let mut items: Vec<TransactWriteItem> = Vec::with_capacity(sealed.len());

        for entry in sealed.into_iter() {
            seen_sk.insert(entry.inner().sk.clone());

            items.push(
                TransactWriteItem::builder()
                    .put(
                        Put::builder()
                            .table_name(&self.table_name)
                            .set_item(Some(entry.try_into()?))
                            .build(),
                    )
                    .build(),
            );
        }

        for index_sk in all_index_keys::<T>() {
            if seen_sk.contains(&index_sk) {
                continue;
            }

            items.push(
                TransactWriteItem::builder()
                    .delete(
                        Delete::builder()
                            .table_name(&self.table_name)
                            .key("pk", AttributeValue::S(pk.clone()))
                            .key("sk", AttributeValue::S(index_sk))
                            .build(),
                    )
                    .build(),
            );
        }

        // Dynamo has a limit of 100 items per transaction
        for items in items.chunks(100) {
            self.db
                .transact_write_items()
                .set_transact_items(Some(items.to_vec()))
                .send()
                .await
                .map_err(|e| PutError::AwsError(e.to_string()))?;
        }

        Ok(())
    }
}
