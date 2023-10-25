mod index_type;
use crate::{operator::Operator, ColumnType};
pub use index_type::IndexType;
use serde::{Deserialize, Serialize};

pub const K_DEFAULT: usize = 6;
pub const M_DEFAULT: usize = 2048;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Tokenizer {
    EdgeNgram { min_gram: usize, max_gram: usize },
    Ngram { token_length: usize },
    Standard,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TokenFilter {
    Upcase,
    Downcase,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Index {
    pub version: usize,

    #[serde(flatten)]
    pub index_type: IndexType,
}

impl Index {
    pub fn new(index_type: IndexType) -> Self {
        Self {
            version: 1,
            index_type,
        }
    }

    pub fn new_match() -> Self {
        Self::new(IndexType::Match {
            token_filters: vec![TokenFilter::Downcase],
            tokenizer: Tokenizer::Ngram { token_length: 3 },
            m: M_DEFAULT,
            k: K_DEFAULT,
            include_original: true,
        })
    }

    pub fn new_ore() -> Self {
        Self::new(IndexType::Ore)
    }

    pub fn new_unique() -> Self {
        Self::new(IndexType::Unique {
            token_filters: vec![],
        })
    }

    pub fn supports(&self, op: &Operator, cast_type: &ColumnType) -> bool {
        self.index_type.supports(op, cast_type)
    }

    pub fn is_orderable(&self) -> bool {
        self.index_type.is_orderable()
    }

    /// String identifier for the index type.
    /// Useful when naming columns
    pub fn as_str(&self) -> &str {
        self.index_type.as_str()
    }
}
