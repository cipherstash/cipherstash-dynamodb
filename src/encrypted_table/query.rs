use aws_sdk_dynamodb::{primitives::Blob, types::AttributeValue};
use cipherstash_client::encryption::{
    compound_indexer::{ComposableIndex, ComposablePlaintext},
    Plaintext,
};
use itertools::Itertools;
use std::marker::PhantomData;

use crate::{
    encrypted_table::Sealed,
    traits::{Decryptable, Searchable},
    IndexType, SingleIndex,
};
use cipherstash_client::encryption::{compound_indexer::CompoundIndex, IndexTerm};

use super::{EncryptedTable, QueryError, Unsealed};

pub struct RawQueryBuilder<'t> {
    table: &'t EncryptedTable,
    parts: Vec<(String, SingleIndex, Plaintext)>,
}

impl<'t> RawQueryBuilder<'t> {
    pub fn new(table: &'t EncryptedTable) -> Self {
        Self {
            table,
            parts: Default::default(),
        }
    }

    pub fn eq(&mut self, name: impl Into<String>, plaintext: impl Into<Plaintext>) -> &mut Self {
        self.parts
            .push((name.into(), SingleIndex::Exact, plaintext.into()));
        self
    }

    pub fn starts_with(
        &mut self,
        name: impl Into<String>,
        plaintext: impl Into<Plaintext>,
    ) -> &mut Self {
        self.parts
            .push((name.into(), SingleIndex::Prefix, plaintext.into()));

        self
    }

    pub async fn send(
        self,
        type_name: &'static str,
        index_by_name: impl Fn(&str, IndexType) -> Option<Box<dyn ComposableIndex>>,
        plaintext_attributes: Vec<&'static str>,
        decryptable_attributes: Vec<&'static str>,
    ) -> Result<Vec<Unsealed>, QueryError> {
        let (index_name, index, plaintext) = self.build(index_by_name)?;

        let index_term = self.table.cipher.compound_query(
            &CompoundIndex::new(index),
            plaintext,
            Some(format!("{}#{}", type_name, index_name)),
            12,
        )?;

        // With DynamoDB queries must always return a single term
        let term = if let IndexTerm::Binary(x) = index_term {
            AttributeValue::B(Blob::new(x))
        } else {
            Err(QueryError::Other(format!(
                "Returned IndexTerm had invalid type: {index_term:?}"
            )))?
        };

        let query = self
            .table
            .db
            .query()
            .table_name(&self.table.table_name)
            .index_name("TermIndex")
            .key_condition_expression("term = :term")
            .expression_attribute_values(":term", term);

        let result = query
            .send()
            .await
            .map_err(|e| QueryError::AwsError(format!("{e:?}")))?;

        let items = result
            .items
            .ok_or_else(|| QueryError::AwsError("Expected items entry on aws response".into()))?;

        let table_entries = Sealed::vec_from(items)?;

        let results = Sealed::unseal_all_raw(
            table_entries,
            plaintext_attributes,
            decryptable_attributes,
            &self.table.cipher,
        )
        .await?;

        Ok(results)
    }

    pub fn build(
        &self,
        index_by_name: impl Fn(&str, IndexType) -> Option<Box<dyn ComposableIndex>>,
    ) -> Result<(String, Box<dyn ComposableIndex>, ComposablePlaintext), QueryError> {
        let items_len = self.parts.len();

        // this is the simplest way to brute force the index names but relies on some gross
        // stringly typing which doesn't feel good
        for perm in self.parts.iter().permutations(items_len) {
            let (indexes, plaintexts): (Vec<(&String, &SingleIndex)>, Vec<&Plaintext>) =
                perm.into_iter().map(|x| ((&x.0, &x.1), &x.2)).unzip();

            let name = indexes.iter().map(|(index_name, _)| index_name).join("#");

            let mut indexes_iter = indexes.iter().map(|(_, index)| **index);

            let index_type = match indexes.len() {
                1 => IndexType::Single(indexes_iter.next().ok_or_else(|| {
                    QueryError::InvalidQuery(
                        "Expected indexes_iter to include have enough components".to_string(),
                    )
                })?),

                2 => IndexType::Compound2((
                    indexes_iter.next().ok_or_else(|| {
                        QueryError::InvalidQuery(
                            "Expected indexes_iter to include have enough components".to_string(),
                        )
                    })?,
                    indexes_iter.next().ok_or_else(|| {
                        QueryError::InvalidQuery(
                            "Expected indexes_iter to include have enough components".to_string(),
                        )
                    })?,
                )),

                x => {
                    return Err(QueryError::InvalidQuery(format!(
                        "Query included an invalid number of components: {x}"
                    )));
                }
            };

            if let Some(index) = index_by_name(name.as_str(), index_type) {
                let mut plaintext = ComposablePlaintext::new(plaintexts[0].clone());

                for p in plaintexts[1..].iter() {
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

pub struct QueryBuilder<'t, T> {
    raw_builder: RawQueryBuilder<'t>,
    __table: PhantomData<T>,
}

impl<'t, T> QueryBuilder<'t, T>
where
    T: Searchable + Decryptable,
{
    pub fn new(table: &'t EncryptedTable) -> Self {
        Self {
            raw_builder: RawQueryBuilder::new(table),
            __table: Default::default(),
        }
    }

    pub fn eq(mut self, name: impl Into<String>, plaintext: impl Into<Plaintext>) -> Self {
        self.raw_builder.eq(name, plaintext);
        self
    }

    pub fn starts_with(mut self, name: impl Into<String>, plaintext: impl Into<Plaintext>) -> Self {
        self.raw_builder.starts_with(name, plaintext);
        self
    }

    pub async fn send(self) -> Result<Vec<T>, QueryError> {
        self.raw_builder
            .send(
                std::any::type_name::<T>(),
                T::index_by_name,
                T::plaintext_attributes(),
                T::decryptable_attributes(),
            )
            .await?
            .into_iter()
            .map(|unsealed| Ok(T::from_unsealed(unsealed)?))
            .collect::<Result<Vec<_>, QueryError>>()
    }
}
