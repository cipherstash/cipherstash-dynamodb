use std::{collections::HashMap, marker::PhantomData};

use crate::{crypto::*, table_entry::TableEntry, DecryptedRecord, EncryptedRecord};
use aws_sdk_dynamodb::{
    types::{AttributeValue, DeleteRequest, Put, TransactWriteItem, WriteRequest},
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
use tokio_stream::StreamExt;

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

    pub async fn delete(&self, pk: &str) -> Result<(), DeleteError> {
        let pk = encrypt_partition_key(pk, &self.cipher)?;

        let paginator = self
            .db
            .query()
            .table_name(&self.table_name)
            .key_condition_expression("pk = :pk")
            .expression_attribute_values(":pk", AttributeValue::S(pk))
            .into_paginator();

        let mut stream = paginator.send();

        let mut items = vec![];

        while let Some(output) = stream.next().await {
            let output = output.map_err(|e| DeleteError::AwsError(e.to_string()))?;

            let output_items = output.items.ok_or_else(|| {
                DeleteError::AwsError("Expected paginated query response to have items".to_string())
            })?;

            for item in output_items {
                let pk = item.get("pk").ok_or_else(|| {
                    DeleteError::AwsError("Expected returned record to have pk field".to_string())
                })?;

                let sk = item.get("sk").ok_or_else(|| {
                    DeleteError::AwsError("Expected returned record to have sk field".to_string())
                })?;

                items.push(
                    WriteRequest::builder()
                        .delete_request(
                            DeleteRequest::builder()
                                .key("pk", pk.clone())
                                .key("sk", sk.clone())
                                .build(),
                        )
                        .build(),
                )
            }
        }

        // Dynamo docs say there is a max number of 25 write items per request
        for item in items.chunks(25).into_iter() {
            let mut request_items = HashMap::new();
            request_items.insert(self.table_name.clone(), item.to_vec());

            self.db
                .batch_write_item()
                .set_request_items(Some(request_items))
                .send()
                .await
                .map_err(|e| DeleteError::AwsError(e.to_string()))?;
        }

        Ok(())
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
