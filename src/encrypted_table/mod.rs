pub mod query;
mod table_entry;
pub use self::{
    query::QueryBuilder,
    table_entry::{TableAttribute, TableEntry, TryFromTableAttr},
};
use crate::{
    crypto::*,
    errors::*,
    traits::{Decryptable, PrimaryKeyError, PrimaryKeyParts, Searchable},
    Identifiable,
};
use aws_sdk_dynamodb::types::{AttributeValue, Delete, Put, TransactWriteItem};
use cipherstash_client::{
    config::{console_config::ConsoleConfig, zero_kms_config::ZeroKMSConfig},
    credentials::{auto_refresh::AutoRefresh, service_credentials::ServiceCredentials},
    encryption::Encryption,
    zero_kms::ZeroKMS,
};
use log::info;
use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
};

pub struct Headless;

pub struct Dynamo {
    pub(crate) db: aws_sdk_dynamodb::Client,
    pub(crate) table_name: String,
}

impl Deref for Dynamo {
    type Target = aws_sdk_dynamodb::Client;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

pub struct EncryptedTable<D = Dynamo> {
    db: D,
    cipher: Box<Encryption<AutoRefresh<ServiceCredentials>>>,
}

impl<D> EncryptedTable<D> {
    // option here to generate query params

    // option here to seal
}

impl EncryptedTable<Headless> {
    pub async fn init_headless() -> Result<Self, InitError> {
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
            db: Headless,
            cipher,
        })
    }
}

/// A patch of records to insert and delete based on an operation
///
/// When inserting records with CipherStash DynamoDB, previous index terms must be deleted in order
/// to maintain data integrity. For a `put` operation this will contain both "put" records and
/// "delete" records.
///
/// When deleting records this patch will only contain "delete" records.
pub struct DynamoRecordPatch {
    pub put_records: Vec<HashMap<String, AttributeValue>>,
    pub delete_records: Vec<PrimaryKeyParts>,
}

impl DynamoRecordPatch {
    /// Consume the [`DynamoRecordPatch`] and create a list of [`TransactWriteItem`] used to put
    /// and delete records from DynamoDB.
    ///
    /// Not that only 100 transact write items can be sent to DynamoDB at one time.
    pub fn into_transact_write_items(
        self,
        table_name: &str,
    ) -> Result<Vec<TransactWriteItem>, BuildError> {
        let mut items = Vec::with_capacity(self.put_records.len() + self.delete_records.len());

        for insert in self.put_records.into_iter() {
            items.push(
                TransactWriteItem::builder()
                    .put(
                        Put::builder()
                            .table_name(table_name)
                            .set_item(Some(insert))
                            .build()?,
                    )
                    .build(),
            );
        }

        for PrimaryKeyParts { pk, sk } in self.delete_records.into_iter() {
            items.push(
                TransactWriteItem::builder()
                    .delete(
                        Delete::builder()
                            .table_name(table_name)
                            .key("pk", AttributeValue::S(pk))
                            .key("sk", AttributeValue::S(sk))
                            .build()?,
                    )
                    .build(),
            );
        }

        Ok(items)
    }
}

impl<D> EncryptedTable<D> {
    pub fn query<S>(&self) -> QueryBuilder<S, D>
    where
        S: Searchable,
    {
        QueryBuilder::new(self)
    }

    pub async fn decrypt_all<T: Decryptable>(
        &self,
        items: impl IntoIterator<Item = HashMap<String, AttributeValue>>,
    ) -> Result<Vec<T>, DecryptError> {
        let table_entries = SealedTableEntry::vec_from(items)?;
        let results = SealedTableEntry::unseal_all(table_entries, &self.cipher).await?;
        Ok(results)
    }

    pub async fn decrypt<T: Decryptable>(
        &self,
        item: HashMap<String, AttributeValue>,
    ) -> Result<T, DecryptError> {
        let table_entry = SealedTableEntry::try_from(item)?;
        let result = table_entry.unseal(&self.cipher).await?;
        Ok(result)
    }

    pub async fn create_delete_patch<E: Searchable + Identifiable>(
        &self,
        k: impl Into<E::PrimaryKey>,
    ) -> Result<DynamoRecordPatch, DeleteError> {
        let PrimaryKeyParts { pk, sk } = self.get_primary_key_parts::<E>(k)?;

        let delete_records = all_index_keys::<E>(&sk)
            .into_iter()
            .map(|x| Ok::<_, DeleteError>(b64_encode(hmac(&x, Some(pk.as_str()), &self.cipher)?)))
            .chain([Ok(sk)])
            .map(|sk| {
                let sk = sk?;
                Ok::<_, DeleteError>(PrimaryKeyParts { pk: pk.clone(), sk })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(DynamoRecordPatch {
            put_records: vec![],
            delete_records,
        })
    }

    /// Create a [`DynamoRecordPatch`] used to insert records into DynamoDB.
    ///
    /// This will create a root record with all attributes and index records that only include
    /// attributes specified by the `index_predicate`. Use this predicate to only project certain
    /// attributes into the index.
    ///
    /// This patch will also include multiple delete items to remove any index keys that could be
    /// remaining in the database after updating a record.
    pub async fn create_put_patch<E: Searchable + Identifiable>(
        &self,
        record: E,
        index_predicate: impl FnMut(&str, &TableAttribute) -> bool,
    ) -> Result<DynamoRecordPatch, PutError> {
        let mut seen_sk = HashSet::new();

        let sealer: Sealer<E> = record.into_sealer()?;
        let sealed = sealer.seal(&self.cipher, 12).await?;

        let mut put_records = Vec::with_capacity(sealed.len());
        let mut delete_records = vec![];

        let PrimaryKeyParts { pk, sk } = sealed.primary_key();

        let (root, index_entries) = sealed.into_table_entries(index_predicate);

        seen_sk.insert(root.inner().sk.clone());
        put_records.push(root.try_into()?);

        for entry in index_entries.into_iter() {
            seen_sk.insert(entry.inner().sk.clone());
            put_records.push(entry.try_into()?);
        }

        for index_sk in all_index_keys::<E>(&sk) {
            let index_sk = b64_encode(hmac(&index_sk, Some(pk.as_str()), &self.cipher)?);

            if seen_sk.contains(&index_sk) {
                continue;
            }

            delete_records.push(PrimaryKeyParts {
                pk: pk.clone(),
                sk: index_sk,
            });
        }

        Ok(DynamoRecordPatch {
            put_records,
            delete_records,
        })
    }

    fn get_primary_key_parts<I: Identifiable>(
        &self,
        k: impl Into<I::PrimaryKey>,
    ) -> Result<PrimaryKeyParts, PrimaryKeyError> {
        I::get_primary_key_parts_from_key(k.into(), &self.cipher)
    }
}

impl EncryptedTable<Dynamo> {
    pub async fn init(
        db: aws_sdk_dynamodb::Client,
        table_name: impl Into<String>,
    ) -> Result<Self, InitError> {
        let table = EncryptedTable::init_headless().await?;

        Ok(Self {
            db: Dynamo {
                table_name: table_name.into(),
                db,
            },
            cipher: table.cipher,
        })
    }

    pub async fn get<T>(&self, k: impl Into<T::PrimaryKey>) -> Result<Option<T>, GetError>
    where
        T: Decryptable + Identifiable,
    {
        let PrimaryKeyParts { pk, sk } = self.get_primary_key_parts::<T>(k)?;

        let result = self
            .db
            .get_item()
            .table_name(&self.db.table_name)
            .key("pk", AttributeValue::S(pk))
            .key("sk", AttributeValue::S(sk))
            .send()
            .await
            .map_err(|e| GetError::Aws(format!("{e:?}")))?;

        if let Some(item) = result.item {
            Ok(Some(self.decrypt(item).await?))
        } else {
            Ok(None)
        }
    }

    pub async fn delete<E: Searchable + Identifiable>(
        &self,
        k: impl Into<E::PrimaryKey>,
    ) -> Result<(), DeleteError> {
        let transact_items = self
            .create_delete_patch::<E>(k)
            .await?
            .into_transact_write_items(&self.db.table_name)?;

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
        T: Searchable + Identifiable,
    {
        let transact_items = self
            .create_put_patch(
                record,
                // include all records in the indexes
                |_, _| true,
            )
            .await?
            .into_transact_write_items(&self.db.table_name)?;

        println!("ITEMS {:#?}", transact_items);

        // Dynamo has a limit of 100 items per transaction
        for items in transact_items.chunks(100) {
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
