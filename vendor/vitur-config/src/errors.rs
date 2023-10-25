use super::{list::DuplicateEntry, ColumnConfig};
use crate::TableConfig;
use std::convert::Infallible;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Further qualification to {0} is not possible with qualifer {1}")]
    UnexpectedQualifier(String, String),
    #[error("'{0}' is not a valid path")]
    InvalidPath(String),
    #[error("Scope qualifiers do no match")]
    MismatchedScope,
    #[error(transparent)]
    Infallible(#[from] Infallible),
    #[error(transparent)]
    DuplicateRelation(#[from] DuplicateEntry<TableConfig>),
    #[error(transparent)]
    DuplicateField(#[from] DuplicateEntry<ColumnConfig>),
}
