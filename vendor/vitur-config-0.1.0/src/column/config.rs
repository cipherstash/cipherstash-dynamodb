use std::collections::HashSet;

use super::index::Index;
use crate::list::ListEntry;
use crate::operator::Operator;
use serde::{Deserialize, Serialize};

// All types should be handled here I guess
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ColumnType {
    BigInt,
    Boolean,
    Date,
    Decimal,
    Float,
    Int,
    SmallInt,
    Timestamp,
    Utf8Str,
    // TODO: What else do we need to add here?
}

impl std::fmt::Display for ColumnType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            ColumnType::BigInt => "BigInt",
            ColumnType::Boolean => "Boolean",
            ColumnType::Date => "Date",
            ColumnType::Decimal => "Decimal",
            ColumnType::Float => "Float",
            ColumnType::Int => "Int",
            ColumnType::SmallInt => "SmallInt",
            ColumnType::Timestamp => "Timestamp",
            ColumnType::Utf8Str => "Utf8Str",
        };

        write!(f, "{text}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ColumnMode {
    /// Store both the plaintext and encrypted data - all operations will continue to be performed
    /// against the plaintext data. This mode should be used while migrating existing data.
    PlaintextDuplicate = 1,
    /// Store both the plaintext and encrypted data, but all operations will be mapped to encrypted
    /// data. In this mode the plaintext is just a backup.
    EncryptedDuplicate = 2,
    /// Only store the encrypted data. This mode should be used once migration is complete so
    /// columns get the maximum protection.
    Encrypted = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnConfig {
    pub name: String,
    pub in_place: bool,
    pub cast_type: ColumnType,
    pub indexes: Vec<Index>,
    pub mode: ColumnMode,
}

impl ListEntry for ColumnConfig {}

// Configs must be unique by name
impl PartialEq for ColumnConfig {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

// Compare a string to a Config based on its column name
impl PartialEq<String> for ColumnConfig {
    fn eq(&self, other: &String) -> bool {
        self.name == *other
    }
}

impl ColumnConfig {
    /// Builds a field with the following defaults:
    ///
    /// Type: Utf8Str,
    /// Mode: EncryptedDuplicate
    /// In Place: false
    pub fn build(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            in_place: false,
            cast_type: ColumnType::Utf8Str,
            indexes: Default::default(),
            mode: ColumnMode::EncryptedDuplicate,
        }
    }

    /// Consumes self and sets the field_type to the given
    /// value
    pub fn casts_as(mut self, field_type: ColumnType) -> Self {
        self.cast_type = field_type;
        self
    }

    /// Consumes self and adds the given index to the list
    /// of indexes
    pub fn add_index(mut self, index: Index) -> Self {
        // TODO: Not all indexes are allowed on all types
        // check first
        self.indexes.push(index);
        self
    }

    pub fn mode(mut self, mode: ColumnMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn supports_operator(&self, op: &Operator) -> bool {
        self.index_for_operator(op).is_some()
    }

    pub fn supported_operations(&self) -> Vec<Operator> {
        let hash: HashSet<Operator> = self
            .indexes
            .iter()
            .flat_map(|i| i.index_type.supported_operations(&self.cast_type))
            .collect();

        hash.into_iter().collect()
    }

    pub fn index_for_operator(&self, op: &Operator) -> Option<&Index> {
        self.indexes
            .iter()
            .find(|i| i.supports(op, &self.cast_type))
    }

    pub fn index_for_sort(&self) -> Option<&Index> {
        self.indexes.iter().find(|i| i.is_orderable())
    }

    /// Sorts indexes by type. Indexes are sorted in place.
    pub fn sort_indexes_by_type(&mut self) {
        self.indexes
            .sort_by(|a, b| a.index_type.as_str().cmp(b.index_type.as_str()));
    }
}
