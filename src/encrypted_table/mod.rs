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
        self.parts
            .push((name.into(), plaintext.into(), Operator::Eq));
        self
    }

    pub fn and_starts_with(
        mut self,
        name: impl Into<String>,
        plaintext: impl Into<Plaintext>,
    ) -> Self {
        self.parts
            .push((name.into(), plaintext.into(), Operator::StartsWith));
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
        let PrimaryKeyParts { mut pk, sk } = k.into().into_parts::<T>();

        if T::is_partition_key_encrypted() {
            pk = encrypt_partition_key(&pk, &self.cipher)?;
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

        let sk_to_delete = all_index_keys::<E>(&sk).into_iter().into_iter().chain([sk]);

        let transact_items = sk_to_delete.map(|sk| {
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

        let sk = record.sort_key();
        let sealer: Sealer<T> = record.into_sealer()?;
        let (pk, sealed) = sealer.seal(&self.cipher, 12).await?;

        // TODO: Use a combinator
        let mut items: Vec<TransactWriteItem> = Vec::with_capacity(sealed.len());

        for entry in table_entries.into_iter() {
            seen_sk.insert(entry.sk.clone());
            let item = Some(to_item(entry)?);
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
