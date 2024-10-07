pub mod query;
mod table_attribute;
mod table_attributes;
mod table_entry;
pub use self::{
    query::QueryBuilder,
    table_attribute::{TableAttribute, TryFromTableAttr},
    table_attributes::TableAttributes,
    table_entry::TableEntry,
};
use crate::{
    crypto::*,
    errors::*,
    traits::{Decryptable, PrimaryKey, PrimaryKeyError, PrimaryKeyParts, Searchable},
    Identifiable, IndexType,
};
use aws_sdk_dynamodb::types::{AttributeValue, Delete, Put, TransactWriteItem};
use cipherstash_client::{
    config::{console_config::ConsoleConfig, zero_kms_config::ZeroKMSConfig},
    credentials::{
        auto_refresh::AutoRefresh,
        service_credentials::{ServiceCredentials, ServiceToken},
        Credentials,
    },
    encryption::Encryption,
    zero_kms::ZeroKMS,
};
use log::info;
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    ops::Deref,
};

/// Index terms are truncated to this length
const DEFAULT_TERM_SIZE: usize = 12;

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
    pub fn cipher(&self) -> &Encryption<impl Credentials<Token = ServiceToken>> {
        self.cipher.as_ref()
    }
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

// FIXME: Remove this (only used for debugging)
#[derive(Debug)]
pub struct PreparedRecord {
    protected_indexes: Cow<'static, [(Cow<'static, str>, IndexType)]>,
    protected_attributes: Cow<'static, [Cow<'static, str>]>,
    sealer: Sealer,
}

pub struct PreparedDelete {
    primary_key: PreparedPrimaryKey,
    protected_indexes: Cow<'static, [(Cow<'static, str>, IndexType)]>,
}

impl PreparedDelete {
    pub fn new<S: Searchable>(k: impl Into<S::PrimaryKey>) -> Self {
        Self::new_from_parts::<S>(
            k.into()
                .into_parts(&S::type_name(), S::sort_key_prefix().as_deref()),
        )
    }

    pub fn new_from_parts<S: Searchable>(k: PrimaryKeyParts) -> Self {
        let primary_key = PreparedPrimaryKey::new_from_parts::<S>(k);
        let protected_indexes = S::protected_indexes();

        Self {
            primary_key,
            protected_indexes,
        }
    }

    pub fn prepared_primary_key(&self) -> PreparedPrimaryKey {
        self.primary_key.clone()
    }

    pub fn protected_indexes(&self) -> &[(Cow<'static, str>, IndexType)] {
        &self.protected_indexes
    }
}

impl PreparedRecord {
    pub(crate) fn new(
        protected_indexes: Cow<'static, [(Cow<'static, str>, IndexType)]>,
        protected_attributes: Cow<'static, [Cow<'static, str>]>,
        sealer: Sealer,
    ) -> Self {
        Self {
            protected_indexes,
            protected_attributes,
            sealer,
        }
    }

    pub fn prepare_record<R>(record: R) -> Result<Self, SealError>
    where
        R: Searchable + Identifiable,
    {
        let type_name = R::type_name();

        let PrimaryKeyParts { pk, sk } = record
            .get_primary_key()
            .into_parts(&type_name, R::sort_key_prefix().as_deref());

        let protected_indexes = R::protected_indexes();
        let protected_attributes = R::protected_attributes();

        // Get the CompositePlaintext, ComposableIndex, name and type for each index
        let unsealed_indexes = protected_indexes
            .iter()
            .map(|(index_name, index_type)| {
                record
                    .attribute_for_index(index_name, *index_type)
                    .and_then(|attr| {
                        R::index_by_name(index_name, *index_type)
                            .map(|index| (attr, index, index_name.clone(), *index_type))
                    })
                    .ok_or(SealError::MissingAttribute(index_name.to_string()))
                    // TODO: Remove
                    .map(|e| {
                        println!("HHHHHHH {:?}", e);
                        e
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let unsealed = record.into_unsealed();

        let sealer = Sealer {
            pk,
            sk,

            is_sk_encrypted: R::is_sk_encrypted(),
            is_pk_encrypted: R::is_pk_encrypted(),

            type_name,

            unsealed_indexes,

            unsealed,
        };

        Ok(PreparedRecord::new(
            protected_indexes,
            protected_attributes,
            sealer,
        ))
    }

    pub fn primary_key_parts(&self) -> PrimaryKeyParts {
        PrimaryKeyParts {
            pk: self.sealer.pk.clone(),
            sk: self.sealer.sk.clone(),
        }
    }

    pub fn type_name(&self) -> &str {
        &self.sealer.type_name
    }

    pub fn protected_indexes(&self) -> &[(Cow<'static, str>, IndexType)] {
        &self.protected_indexes
    }
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
    pub fn query<S>(&self) -> QueryBuilder<S, &Self>
    where
        S: Searchable,
    {
        QueryBuilder::with_backend(self)
    }

    pub async fn unseal_all(
        &self,
        items: impl IntoIterator<Item = HashMap<String, AttributeValue>>,
        spec: UnsealSpec<'_>,
    ) -> Result<Vec<Unsealed>, DecryptError> {
        let table_entries = SealedTableEntry::vec_from(items)?;
        dbg!(&table_entries);
        let results = SealedTableEntry::unseal_all(table_entries, spec, &self.cipher).await?;
        Ok(results)
    }

    pub async fn unseal(
        &self,
        item: HashMap<String, AttributeValue>,
        spec: UnsealSpec<'_>,
    ) -> Result<Unsealed, DecryptError> {
        let table_entry = SealedTableEntry::try_from(item)?;
        let result = table_entry.unseal(spec, &self.cipher).await?;
        Ok(result)
    }

    pub async fn decrypt_all<T: Decryptable>(
        &self,
        items: impl IntoIterator<Item = HashMap<String, AttributeValue>>,
    ) -> Result<Vec<T>, DecryptError> {
        let items = self
            .unseal_all(items, UnsealSpec::new_for_decryptable::<T>())
            .await?;

        Ok(items
            .into_iter()
            .map(|x| x.into_value::<T>())
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub async fn decrypt<T: Decryptable>(
        &self,
        item: HashMap<String, AttributeValue>,
    ) -> Result<T, DecryptError> {
        let item = self
            .unseal(item, UnsealSpec::new_for_decryptable::<T>())
            .await?;

        Ok(item.into_value()?)
    }

    pub async fn create_delete_patch(
        &self,
        delete: PreparedDelete,
    ) -> Result<DynamoRecordPatch, DeleteError> {
        let PrimaryKeyParts { pk, sk } = self.encrypt_primary_key_parts(delete.primary_key)?;

        let delete_records = all_index_keys(&sk, delete.protected_indexes)
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
    pub async fn create_put_patch(
        &self,
        record: PreparedRecord,
        // TODO: Make sure the index_predicate is used correctly
        index_predicate: impl FnMut(&str, &TableAttribute) -> bool,
    ) -> Result<DynamoRecordPatch, PutError> {
        let mut seen_sk = HashSet::new();

        let PreparedRecord {
            protected_attributes,
            protected_indexes,
            sealer,
        } = record;

        let sealed = sealer
            .seal(protected_attributes, &self.cipher, DEFAULT_TERM_SIZE)
            .await?;

        let mut put_records = Vec::with_capacity(sealed.len());

        // When doing an upsert you need to delete any index keys that are not used for the current
        // record but may have been used for previous records.
        let mut delete_records = vec![];

        let PrimaryKeyParts { pk, sk } = sealed.primary_key();

        let (root, index_entries) = sealed.into_table_entries(index_predicate);

        seen_sk.insert(root.inner().sk.clone());
        put_records.push(root.try_into()?);

        for entry in index_entries.into_iter() {
            seen_sk.insert(entry.inner().sk.clone());
            put_records.push(entry.try_into()?);
        }

        for index_sk in all_index_keys(&sk, protected_indexes) {
            let index_sk = b64_encode(hmac(&index_sk, Some(pk.as_str()), &self.cipher)?);

            // If the current put has an index with the specified key then don't delete it.
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

    /// Take a prepared primary key and encrypt it to get the [`PrimaryKeyParts`] which can be used
    /// for retrieval.
    pub fn encrypt_primary_key_parts(
        &self,
        prepared_primary_key: PreparedPrimaryKey,
    ) -> Result<PrimaryKeyParts, PrimaryKeyError> {
        let PrimaryKeyParts { mut pk, mut sk } = prepared_primary_key.primary_key_parts;

        if prepared_primary_key.is_pk_encrypted {
            pk = b64_encode(hmac(&pk, None, &self.cipher)?);
        }

        if prepared_primary_key.is_sk_encrypted {
            sk = b64_encode(hmac(&sk, Some(pk.as_str()), &self.cipher)?);
        }

        Ok(PrimaryKeyParts { pk, sk })
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
        let PrimaryKeyParts { pk, sk } =
            self.encrypt_primary_key_parts(PreparedPrimaryKey::new::<T>(k))?;

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
            .create_delete_patch(PreparedDelete::new::<E>(k))
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
        let record = PreparedRecord::prepare_record(record)?;

        let transact_items = self
            .create_put_patch(
                record,
                // include all records in the indexes
                |_, _| true,
            )
            .await?
            .into_transact_write_items(&self.db.table_name)?;

        // Dynamo has a limit of 100 items per transaction
        for items in transact_items.chunks(100) {
            self.db
                .transact_write_items()
                .set_transact_items(Some(items.to_vec()))
                .send()
                .await?;
        }

        Ok(())
    }
}
