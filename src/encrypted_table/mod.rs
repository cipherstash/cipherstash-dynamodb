pub mod query;
mod table_entry;
pub use self::{
    query::{QueryBuilder, RawQueryBuilder},
    table_entry::{TableAttribute, TableEntry, TryFromTableAttr},
};
use crate::{
    crypto::*,
    errors::*,
    traits::{Decryptable, PrimaryKey, PrimaryKeyParts, Searchable},
    Encryptable,
};
use aws_sdk_dynamodb::{
    types::{AttributeValue, Delete, Put, TransactWriteItem},
    Client,
};
use cipherstash_client::{
    config::{console_config::ConsoleConfig, zero_kms_config::ZeroKMSConfig},
    credentials::{auto_refresh::AutoRefresh, service_credentials::ServiceCredentials},
    encryption::{Encryption, EncryptionError},
    zero_kms::{DatasetConfigWithIndexRootKey, ZeroKMS},
};
use log::info;
use std::collections::HashSet;

pub struct EncryptedTable {
    db: Client,
    cipher: Box<Encryption<AutoRefresh<ServiceCredentials>>>,
    // We may use this later but for now the config is in code
    _dataset_config: DatasetConfigWithIndexRootKey,
    table_name: String,
}

impl EncryptedTable {
    pub fn cipher(&self) -> &Encryption<AutoRefresh<ServiceCredentials>> {
        &self.cipher
    }

    pub async fn init(
        db: aws_sdk_dynamodb::Client,
        table_name: impl Into<String>,
    ) -> Result<EncryptedTable, InitError> {
        info!("Initializing...");
        let console_config = ConsoleConfig::builder().with_env().build()?;
        let zero_kms_config = ZeroKMSConfig::builder()
            .decryption_log(true)
            .with_env()
            .console_config(&console_config)
            .build_with_client_key()?;

        let zero_kms_client = ZeroKMS::new_with_client_key(
            &zero_kms_config.base_url(),
            AutoRefresh::new(zero_kms_config.credentials()),
            zero_kms_config.decryption_log_path().as_deref(),
            zero_kms_config.client_key(),
        );

        info!("Fetching dataset config...");
        let dataset_config = zero_kms_client.load_dataset_config().await?;
        let cipher = Box::new(Encryption::new(
            dataset_config.index_root_key,
            zero_kms_client,
        ));

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

    pub fn query_raw(&self) -> RawQueryBuilder {
        RawQueryBuilder::new(self)
    }

    pub fn get_primary_key_parts<T: Encryptable>(
        &self,
        k: impl Into<T::PrimaryKey>,
    ) -> Result<PrimaryKeyParts, EncryptionError> {
        self.get_primary_key_parts_raw(
            k.into().into_parts::<T>(),
            T::is_partition_key_encrypted(),
            T::is_sort_key_encrypted(),
        )
    }

    pub fn get_primary_key_parts_raw(
        &self,
        PrimaryKeyParts { mut pk, mut sk }: PrimaryKeyParts,
        is_partition_key_encrypted: bool,
        is_sort_key_encrypted: bool,
    ) -> Result<PrimaryKeyParts, EncryptionError> {
        if is_partition_key_encrypted {
            pk = b64_encode(hmac(&pk, None, &self.cipher)?);
        }

        if is_sort_key_encrypted {
            sk = b64_encode(hmac(&sk, Some(pk.as_str()), &self.cipher)?);
        }

        Ok(PrimaryKeyParts { pk, sk })
    }

    pub async fn get<T>(&self, k: impl Into<T::PrimaryKey>) -> Result<Option<T>, GetError>
    where
        T: Decryptable,
    {
        let primary_key_parts = self.get_primary_key_parts::<T>(k)?;

        if let Some(unsealed) = self
            .get_raw(
                primary_key_parts,
                T::plaintext_attributes(),
                T::decryptable_attributes(),
            )
            .await?
        {
            Ok(Some(T::from_unsealed(unsealed)?))
        } else {
            Ok(None)
        }
    }

    pub async fn get_raw(
        &self,
        PrimaryKeyParts { pk, sk }: PrimaryKeyParts,
        plaintext_attributes: &[&'static str],
        decryptable_attributes: &[&'static str],
    ) -> Result<Option<Unsealed>, GetError> {
        let result = self
            .db
            .get_item()
            .table_name(&self.table_name)
            .key("pk", AttributeValue::S(pk))
            .key("sk", AttributeValue::S(sk))
            .send()
            .await
            .map_err(|e| GetError::Aws(format!("{e:?}")))?;

        let Some(item) = result.item else {
            return Ok(None);
        };

        Ok(Some(
            Sealed::try_from(item)?
                .unseal_raw(plaintext_attributes, decryptable_attributes, &self.cipher)
                .await?,
        ))
    }

    pub async fn delete<E: Searchable>(
        &self,
        k: impl Into<E::PrimaryKey>,
    ) -> Result<(), DeleteError> {
        let primary_key_parts = self.get_primary_key_parts::<E>(k)?;
        let all_index_keys = all_index_keys::<E>(&primary_key_parts.sk);

        self.delete_raw(primary_key_parts, all_index_keys).await
    }

    pub async fn delete_raw(
        &self,
        PrimaryKeyParts { pk, sk }: PrimaryKeyParts,
        all_index_keys: Vec<String>,
    ) -> Result<(), DeleteError> {
        let transact_items = all_index_keys
            .into_iter()
            .map(|x| Ok::<_, DeleteError>(b64_encode(hmac(&x, Some(pk.as_str()), &self.cipher)?)))
            .chain([Ok(sk)])
            .map(|sk| {
                sk.and_then(|sk| {
                    Ok::<_, DeleteError>(
                        TransactWriteItem::builder()
                            .delete(
                                Delete::builder()
                                    .table_name(&self.table_name)
                                    .key("pk", AttributeValue::S(pk.clone()))
                                    .key("sk", AttributeValue::S(sk))
                                    .build()?,
                            )
                            .build(),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Dynamo has a limit of 100 items per transaction
        for items in transact_items.chunks(100) {
            self.db
                .transact_write_items()
                .set_transact_items(Some(items.to_vec()))
                .send()
                .await
                .map_err(|e| DeleteError::Aws(format!("{e:?}")))?;
        }

        Ok(())
    }

    pub async fn put<T>(&self, record: T) -> Result<(), PutError>
    where
        T: Searchable,
    {
        let (primary_key_parts, sealed) = Sealer::seal(record, &self.cipher).await?;
        let all_index_keys = all_index_keys::<T>(&primary_key_parts.sk);

        self.put_raw(primary_key_parts, sealed, all_index_keys)
            .await
    }

    pub async fn put_raw(
        &self,
        PrimaryKeyParts { pk, .. }: PrimaryKeyParts,
        sealed: Vec<Sealed>,
        all_index_keys: Vec<String>,
    ) -> Result<(), PutError> {
        let mut seen_sk = HashSet::new();
        let mut items: Vec<TransactWriteItem> = Vec::with_capacity(sealed.len());

        for entry in sealed.into_iter() {
            seen_sk.insert(entry.inner().sk.clone());

            items.push(
                TransactWriteItem::builder()
                    .put(
                        Put::builder()
                            .table_name(&self.table_name)
                            .set_item(Some(entry.try_into()?))
                            .build()?,
                    )
                    .build(),
            );
        }

        for index_sk in all_index_keys {
            let index_sk = b64_encode(hmac(&index_sk, Some(pk.as_str()), &self.cipher)?);

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
                            .build()?,
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
