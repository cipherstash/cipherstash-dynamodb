pub mod query;
mod table_entry;
pub use self::{
    query::{QueryBuilder, QueryError},
    table_entry::{TableAttribute, TableEntry},
};
use crate::{
    crypto::*,
    traits::{
        Decryptable, PrimaryKey, PrimaryKeyParts, ReadConversionError, Searchable,
        WriteConversionError,
    },
    Encryptable,
};
use aws_sdk_dynamodb::{
    types::{AttributeValue, Delete, Put, TransactWriteItem},
    Client,
};
use cipherstash_client::{
    config::{console_config::ConsoleConfig, errors::ConfigError, vitur_config::ViturConfig},
    credentials::{auto_refresh::AutoRefresh, vitur_credentials::ViturCredentials},
    encryption::{Encryption, EncryptionError},
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
    Aws(String),
    #[error("Write Conversion Error: {0}")]
    WriteConversion(#[from] WriteConversionError),
    #[error("SealError: {0}")]
    Seal(#[from] SealError),
    #[error("CryptoError: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Encryption Error: {0}")]
    Encryption(#[from] EncryptionError),
}

#[derive(Error, Debug)]
pub enum GetError {
    #[error("SealError: {0}")]
    Seal(#[from] SealError),
    #[error("Encryption Error: {0}")]
    Encryption(#[from] EncryptionError),
    #[error("AwsError: {0}")]
    Aws(String),
    #[error("Read Conversion Error: {0}")]
    ReadConversion(#[from] ReadConversionError),
}

#[derive(Error, Debug)]
pub enum DeleteError {
    #[error("Encryption Error: {0}")]
    Encryption(#[from] EncryptionError),
    #[error("AwsError: {0}")]
    Aws(String),
}

#[derive(Error, Debug)]
pub enum InitError {
    #[error("ConfigError: {0}")]
    Config(#[from] ConfigError),
    #[error("LoadConfigError: {0}")]
    LoadConfig(#[from] LoadConfigError),
}

impl EncryptedTable {
    pub async fn init(
        db: aws_sdk_dynamodb::Client,
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
        R: Searchable + Decryptable,
    {
        QueryBuilder::new(self)
    }

    fn get_primary_key_parts<T: Encryptable>(
        &self,
        k: impl Into<T::PrimaryKey>,
    ) -> Result<PrimaryKeyParts, EncryptionError> {
        let PrimaryKeyParts { mut pk, mut sk } = k.into().into_parts::<T>();

        if T::is_partition_key_encrypted() {
            pk = hmac("pk", &pk, None, &self.cipher)?;
        }

        if T::is_sort_key_encrypted() {
            sk = hmac("sk", &sk, Some(pk.as_str()), &self.cipher)?;
        }

        Ok(PrimaryKeyParts { pk, sk })
    }

    pub async fn get<T>(&self, k: impl Into<T::PrimaryKey>) -> Result<Option<T>, GetError>
    where
        T: Decryptable,
    {
        let PrimaryKeyParts { pk, sk } = self.get_primary_key_parts::<T>(k)?;

        let result = self
            .db
            .get_item()
            .table_name(&self.table_name)
            .key("pk", AttributeValue::S(pk))
            .key("sk", AttributeValue::S(sk))
            .send()
            .await
            .map_err(|e| GetError::Aws(format!("{e:?}")))?;

        let sealed: Option<Sealed> = result.item.map(Sealed::try_from).transpose()?;

        if let Some(sealed) = sealed {
            Ok(Some(sealed.unseal(&self.cipher).await?))
        } else {
            Ok(None)
        }
    }

    pub async fn delete<E: Searchable>(
        &self,
        k: impl Into<E::PrimaryKey>,
    ) -> Result<(), DeleteError> {
        let PrimaryKeyParts { pk, sk } = self.get_primary_key_parts::<E>(k)?;

        let sk_to_delete = all_index_keys::<E>(&sk)
            .into_iter()
            .map(|x| hmac("sk", &x, Some(pk.as_str()), &self.cipher))
            .chain([Ok(sk)])
            .collect::<Result<Vec<_>, _>>()?;

        let transact_items = sk_to_delete.into_iter().map(|sk| {
            TransactWriteItem::builder()
                .delete(
                    Delete::builder()
                        .table_name(&self.table_name)
                        .key("pk", AttributeValue::S(pk.clone()))
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
                .map_err(|e| DeleteError::Aws(format!("{e:?}")))?;
        }

        Ok(())
    }

    pub async fn put<T>(&self, record: T) -> Result<(), PutError>
    where
        // TODO: We may want to create a separate put_with_indexes function for Searchable types
        T: Searchable,
    {
        let mut seen_sk = HashSet::new();

        let sealer: Sealer<T> = record.into_sealer()?;
        let (PrimaryKeyParts { pk, sk }, sealed) = sealer.seal(&self.cipher, 12).await?;

        // TODO: Use a combinator
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

        for index_sk in all_index_keys::<T>(&sk) {
            let index_sk = hmac("sk", &index_sk, Some(pk.as_str()), &self.cipher)?;

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
                .map_err(|e| PutError::Aws(format!("{e:?}")))?;
        }

        Ok(())
    }
}
