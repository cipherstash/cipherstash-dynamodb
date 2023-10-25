use crate::errors::ConfigError;
use crate::list::{ListEntry, UniqueList};
use crate::ColumnConfig;
use std::fmt::Debug;

use super::TablePath;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableConfig {
    pub path: TablePath,
    pub fields: UniqueList<ColumnConfig>,
}

impl ListEntry for TableConfig {}

impl PartialEq for TableConfig {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl PartialEq<TablePath> for TableConfig {
    fn eq(&self, other: &TablePath) -> bool {
        self.path == *other
    }
}

impl PartialEq<&str> for TableConfig {
    fn eq(&self, other: &&str) -> bool {
        match TablePath::try_from(*other) {
            Ok(path) => self.path == path,
            Err(_) => false,
        }
    }
}

impl TableConfig {
    pub fn new<R>(path: R) -> Result<Self, ConfigError>
    where
        R: TryInto<TablePath>,
        <R as TryInto<TablePath>>::Error: Debug,
        ConfigError: From<<R as TryInto<TablePath>>::Error>,
    {
        let path: TablePath = path.try_into()?;
        Ok(Self {
            path,
            fields: Default::default(),
        })
    }

    pub fn add_column(mut self, field: ColumnConfig) -> Result<Self, ConfigError> {
        self.fields.try_insert(field)?;
        Ok(self)
    }

    pub fn get_column(
        &self,
        name: impl Into<String>,
    ) -> Result<Option<&ColumnConfig>, ConfigError> {
        let name: String = name.try_into()?;
        Ok(self.fields.get(&name))
    }

    pub fn has_column(&self, name: impl Into<String>) -> Result<bool, ConfigError> {
        let name: String = name.try_into()?;
        Ok(self.fields.has_entry(&name))
    }

    /// Sorts all indexes by type for each field. Indexes are sorted in place.
    pub fn sort_indexes_by_type(&mut self) {
        self.fields
            .iter_mut()
            .for_each(ColumnConfig::sort_indexes_by_type);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn add_and_get_column() -> Result<(), Box<dyn Error>> {
        let config = TableConfig::new("users")?.add_column(ColumnConfig::build("name"))?;

        assert!(matches!(
            config.get_column("name")?,
            Some(ColumnConfig { name, .. }) if name == "name"
        ));

        Ok(())
    }

    #[test]
    fn add_dupe() -> Result<(), Box<dyn Error>> {
        let config = TableConfig::new("users")?.add_column(ColumnConfig::build("name"))?;

        assert!(config.add_column(ColumnConfig::build("name")).is_err());

        Ok(())
    }
}
