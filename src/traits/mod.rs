pub use crate::encrypted_table::{TableAttribute, TryFromTableAttr};
use crate::{
    crypto::{SealError, Unsealed},
    errors::QueryError,
};
pub use cipherstash_client::encryption::{
    compound_indexer::{
        ComposableIndex, ComposablePlaintext, CompoundIndex, ExactIndex, PrefixIndex,
    },
    Plaintext, PlaintextNullVariant, TryFromPlaintext,
};

mod primary_key;
pub use primary_key::*;

use std::fmt::{Debug, Display};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SingleIndex {
    Exact,
    Prefix,
}

impl Display for SingleIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exact => f.write_str("exact"),
            Self::Prefix => f.write_str("prefix"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IndexType {
    Single(SingleIndex),
    Compound2((SingleIndex, SingleIndex)),
}

impl IndexType {
    pub fn from_single_index_iter<I>(index_iter: I) -> Result<Self, QueryError>
    where
        I: IntoIterator<Item = SingleIndex>,
        I::IntoIter: ExactSizeIterator,
    {
        let mut indexes_iter = index_iter.into_iter();

        match indexes_iter.len() {
            1 => Ok(IndexType::Single(indexes_iter.next().ok_or_else(|| {
                QueryError::InvalidQuery(
                    "Expected indexes_iter to include have enough components".to_string(),
                )
            })?)),

            2 => Ok(IndexType::Compound2((
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
            ))),
            x => Err(QueryError::InvalidQuery(format!(
                "Query included an invalid number of components: {x}"
            ))),
        }
    }
}

impl Display for IndexType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single(index) => Display::fmt(index, f),
            Self::Compound2((index_a, index_b)) => {
                Display::fmt(index_a, f)?;
                f.write_str(":")?;
                Display::fmt(index_b, f)?;
                Ok(())
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum ReadConversionError {
    #[error("Missing attribute: {0}")]
    NoSuchAttribute(String),
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    #[error("Failed to convert attribute: {0} from Plaintext")]
    ConversionFailed(String),
}

#[derive(Debug, Error)]
pub enum WriteConversionError {
    #[error("Failed to convert attribute: '{0}' to Plaintext")]
    ConversionFailed(String),
}

pub trait Encryptable: Debug + Sized {
    type PrimaryKey: PrimaryKey;

    fn type_name() -> &'static str;

    fn sort_key_prefix() -> Option<&'static str>;

    fn is_partition_key_encrypted() -> bool;

    fn is_sort_key_encrypted() -> bool;

    fn sort_key(&self) -> String {
        Self::type_name().into()
    }

    fn partition_key(&self) -> String;

    fn protected_attributes() -> Vec<&'static str>;

    fn plaintext_attributes() -> Vec<&'static str> {
        vec![]
    }

    fn into_unsealed(self) -> Unsealed;
}

pub trait Searchable: Encryptable {
    fn attribute_for_index(
        &self,
        _index_name: &str,
        _index_type: IndexType,
    ) -> Option<ComposablePlaintext> {
        None
    }

    /// Returns attributes for all indexes in the same order as [Self::protected_indexes]
    fn all_attributes_for_indexes(&self) -> Vec<ComposablePlaintext> {
        Self::protected_indexes()
            .iter()
            .map(|&(index_name, index_type)| {
                self.attribute_for_index(index_name, index_type)
                    .expect("No attribute for index")
            })
            .collect()
    }

    fn protected_indexes() -> Vec<(&'static str, IndexType)> {
        vec![]
    }

    fn index_by_name(
        _index_name: &str,
        _index_type: IndexType,
    ) -> Option<Box<dyn ComposableIndex>> {
        None
    }
}

pub trait Decryptable: Encryptable {
    /// Convert an `Unsealed` into a `Self`.

    fn from_unsealed(unsealed: Unsealed) -> Result<Self, SealError>;

    /// Defines which attributes are decryptable for this type.
    /// Must be equal to or a subset of protected_attributes().
    /// By default, this is the same as protected_attributes().
    fn decryptable_attributes() -> Vec<&'static str> {
        Self::protected_attributes()
    }
}
