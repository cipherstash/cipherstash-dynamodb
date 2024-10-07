use aws_sdk_dynamodb::{primitives::Blob, types::AttributeValue};
use cipherstash_client::{
    credentials::{service_credentials::ServiceToken, Credentials},
    encryption::{
        compound_indexer::{ComposableIndex, ComposablePlaintext},
        Encryption, Plaintext,
    },
};
use itertools::Itertools;
use std::{borrow::Cow, collections::HashMap, marker::PhantomData};

use crate::{
    traits::{Decryptable, Searchable},
    Identifiable, IndexType, SingleIndex,
};
use cipherstash_client::encryption::{compound_indexer::CompoundIndex, IndexTerm};

use super::{Dynamo, EncryptedTable, QueryError};

pub struct QueryBuilder<S, B = ()> {
    parts: Vec<(String, SingleIndex, Plaintext)>,
    backend: B,
    __searchable: PhantomData<S>,
}

pub struct PreparedQuery {
    index_name: String,
    type_name: String,
    composed_index: Box<dyn ComposableIndex + Send>,
    plaintext: ComposablePlaintext,
}

impl PreparedQuery {
    pub async fn encrypt(
        self,
        cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
    ) -> Result<AttributeValue, QueryError> {
        let PreparedQuery {
            index_name,
            composed_index,
            plaintext,
            type_name,
        } = self;

        let index_term = cipher.compound_query(
            &CompoundIndex::new(composed_index),
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

        Ok(term)
    }

    pub async fn send(
        self,
        table: &EncryptedTable<Dynamo>,
    ) -> Result<Vec<HashMap<String, AttributeValue>>, QueryError> {
        let term = self.encrypt(&table.cipher).await?;

        let query = table
            .db
            .query()
            .table_name(&table.db.table_name)
            .index_name("TermIndex")
            .key_condition_expression("term = :term")
            .expression_attribute_values(":term", term);

        let result = query
            .send()
            .await?;

        dbg!(&result);

        let items = result
            .items
            .ok_or_else(|| QueryError::Other("Expected items entry on aws response".into()))?;

        Ok(items)
    }
}

impl<S> Default for QueryBuilder<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> QueryBuilder<S> {
    pub fn new() -> Self {
        Self {
            parts: vec![],
            backend: Default::default(),
            __searchable: Default::default(),
        }
    }
}

impl<S, B> QueryBuilder<S, B> {
    pub fn with_backend(backend: B) -> Self {
        Self {
            parts: vec![],
            backend,
            __searchable: Default::default(),
        }
    }

    pub fn eq(mut self, name: impl Into<String>, plaintext: impl Into<Plaintext>) -> Self {
        self.parts
            .push((name.into(), SingleIndex::Exact, plaintext.into()));
        self
    }

    pub fn starts_with(mut self, name: impl Into<String>, plaintext: impl Into<Plaintext>) -> Self {
        self.parts
            .push((name.into(), SingleIndex::Prefix, plaintext.into()));
        self
    }
}

impl<S, B> QueryBuilder<S, B>
where
    S: Searchable,
{
    pub fn build(self) -> Result<PreparedQuery, QueryError> {
        PreparedQueryBuilder::new::<S>().build(self.parts)
    }
}

impl<S> QueryBuilder<S, &EncryptedTable<Dynamo>>
where
    S: Searchable + Identifiable,
{
    pub async fn load<T: Decryptable>(self) -> Result<Vec<T>, QueryError> {
        let table = self.backend;
        let query = self.build()?;

        let items = query.send(table).await?;
        let results = table.decrypt_all(items).await?;

        Ok(results)
    }
}

impl<S> QueryBuilder<S, &EncryptedTable<Dynamo>>
where
    S: Searchable + Decryptable + Identifiable,
{
    pub async fn send(self) -> Result<Vec<S>, QueryError> {
        self.load::<S>().await
    }
}

pub struct PreparedQueryBuilder {
    pub type_name: Cow<'static, str>,
    pub index_by_name: fn(&str, IndexType) -> Option<Box<dyn ComposableIndex + Send>>,
}

impl PreparedQueryBuilder {
    pub fn new<S: Searchable>() -> Self {
        Self {
            type_name: S::type_name(),
            index_by_name: S::index_by_name,
        }
    }

    pub fn build(
        &self,
        parts: Vec<(String, SingleIndex, Plaintext)>,
    ) -> Result<PreparedQuery, QueryError> {
        let items_len = parts.len();

        // this is the simplest way to brute force the index names but relies on some gross
        // stringly typing which doesn't feel good
        for perm in parts.iter().permutations(items_len) {
            let (indexes, plaintexts): (Vec<(&String, &SingleIndex)>, Vec<&Plaintext>) =
                perm.into_iter().map(|x| ((&x.0, &x.1), &x.2)).unzip();

            let index_name = indexes.iter().map(|(index_name, _)| index_name).join("#");

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

            if let Some(composed_index) = (self.index_by_name)(index_name.as_str(), index_type) {
                let mut plaintext = ComposablePlaintext::new(plaintexts[0].clone());

                for p in plaintexts[1..].iter() {
                    plaintext = plaintext
                        .try_compose((*p).clone())
                        .expect("Failed to compose");
                }

                return Ok(PreparedQuery {
                    index_name,
                    type_name: self.type_name.to_string(),
                    plaintext,
                    composed_index,
                });
            }
        }

        let fields = parts.iter().map(|x| &x.0).join(",");

        Err(QueryError::InvalidQuery(format!(
            "Could not build query for fields: {fields}"
        )))
    }
}
