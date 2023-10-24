use aws_sdk_dynamodb::types::AttributeValue;
use cipherstash_client::encryption::{
    compound_indexer::{ComposableIndex, ComposablePlaintext, Operator},
    EncryptionError, Plaintext,
};
use itertools::Itertools;
use serde_dynamo::from_items;
use std::marker::PhantomData;
use thiserror::Error;

use crate::{
    crypto::{decrypt, CryptoError},
    table_entry::TableEntry,
    DecryptedRecord, SearchableRecord,
};
use cipherstash_client::encryption::{compound_indexer::CompoundIndex, IndexTerm};

use super::EncryptedTable;

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

pub struct QueryBuilder<'t, T> {
    parts: Vec<(String, Plaintext, Operator)>,
    table: &'t EncryptedTable,
    __table: PhantomData<T>,
}

impl<'t, T> QueryBuilder<'t, T>
where
    T: SearchableRecord + DecryptedRecord,
{
    pub fn new(table: &'t EncryptedTable) -> Self {
        Self {
            parts: vec![],
            table,
            __table: Default::default(),
        }
    }

    pub fn eq(mut self, name: impl Into<String>, plaintext: impl Into<Plaintext>) -> Self {
        self.parts
            .push((name.into(), plaintext.into(), Operator::Eq));
        self
    }

    pub fn starts_with(mut self, name: impl Into<String>, plaintext: impl Into<Plaintext>) -> Self {
        self.parts
            .push((name.into(), plaintext.into(), Operator::StartsWith));
        self
    }

    pub async fn send(self) -> Result<Vec<T>, QueryError> {
        let (index_name, index, plaintext, builder) = self.build()?;

        let index_term = builder.table.cipher.compound_query(
            &CompoundIndex::new(index),
            plaintext,
            Some(format!("{}#{}", T::type_name(), index_name)),
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

        let query = builder
            .table
            .db
            .query()
            .table_name(&builder.table.table_name)
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

        let mut results: Vec<T> = Vec::with_capacity(table_entries.len());

        // TODO: Bulk Decrypt
        for te in table_entries.into_iter() {
            let attributes = decrypt(te.attributes, &builder.table.cipher).await?;
            let record: T = T::from_attributes(attributes);
            results.push(record);
        }

        Ok(results)
    }

    fn build(
        self,
    ) -> Result<(String, Box<dyn ComposableIndex>, ComposablePlaintext, Self), QueryError> {
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

                return Ok((name, index, plaintext, self));
            }
        }

        let fields = self.parts.iter().map(|x| &x.0).join(",");

        Err(QueryError::InvalidQuery(format!(
            "Could not build query for fields: {fields}"
        )))
    }
}
