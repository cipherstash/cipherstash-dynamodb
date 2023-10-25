use crate::{errors::ConfigError, list::UniqueList, TableConfig};
use serde::{Deserialize, Serialize};

/// Struct to manage the config for a given database.
/// At connection time, the Driver will retrieve config from Vitur
/// for the currently connected database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetConfig {
    pub tables: UniqueList<TableConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetConfigWithIndexRootKey {
    /// The "root key" used for deriving ORE and bloom filter keys used in indexes
    pub index_root_key: [u8; 32],
    #[serde(flatten)]
    pub config: DatasetConfig,
}

impl DatasetConfig {
    pub fn init() -> Self {
        Self {
            tables: Default::default(),
        }
    }

    pub fn add_table(mut self, config: TableConfig) -> Result<Self, ConfigError> {
        self.tables.try_insert(config)?;

        Ok(self)
    }

    /// Returns true if a table matches the given query
    pub fn has_table<Q>(&self, query: &Q) -> bool
    where
        TableConfig: PartialEq<Q>,
    {
        self.get_table(query).is_some()
    }

    /// Finds a table that matches `query`
    pub fn get_table<Q>(&self, query: &Q) -> Option<&TableConfig>
    where
        TableConfig: PartialEq<Q>,
    {
        self.tables.get(query)
    }

    /// Sorts all indexes by type for each field in each table. Indexes are sorted in place.
    ///
    /// This is useful for ensuring that iteration over indexes always occurs in order
    /// by type (instead of the order that they appear in a config file or the order of
    /// `ColumnConfig::add_index` calls).
    pub fn sort_indexes_by_type(mut self) -> Self {
        self.tables
            .iter_mut()
            .for_each(TableConfig::sort_indexes_by_type);

        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use std::error::Error;
    use toml::to_string_pretty;

    use crate::*;

    #[test]
    fn add_and_get_table() -> Result<(), Box<dyn Error>> {
        let config = DatasetConfig::init().add_table(TableConfig::new("users")?)?;

        assert!(matches!(
            config.get_table(&"users"),
            Some(TableConfig { path, .. }) if path.as_string() == "users"
        ));

        Ok(())
    }

    #[test]
    fn add_and_get_table_with_schema() -> Result<(), Box<dyn Error>> {
        let config = DatasetConfig::init().add_table(TableConfig::new("public.users")?)?;

        assert!(matches!(
            config.get_table(&"users"),
            Some(TableConfig { path, .. }) if path.as_string() == "public.users"
        ));

        Ok(())
    }

    #[test]
    fn test_serialise_to_toml_single_table() -> Result<(), Box<dyn Error>> {
        let config = DatasetConfig::init().add_table(TableConfig::new("test")?)?;

        assert_eq!(
            to_string_pretty(&config)?,
            indoc! { r#"
                [[tables]]
                path = "test"
                fields = []
            "#}
        );

        Ok(())
    }

    #[test]
    fn test_serialise_to_toml_multiple_table() -> Result<(), Box<dyn Error>> {
        let config = DatasetConfig::init()
            .add_table(TableConfig::new("test")?)?
            .add_table(
                TableConfig::new("another")?.add_column(
                    ColumnConfig::build("great-column")
                        .add_index(column::Index::new_ore())
                        .add_index(column::Index::new_match()),
                )?,
            )?;

        assert_eq!(
            to_string_pretty(&config)?,
            indoc! { r#"
                [[tables]]
                path = "test"
                fields = []

                [[tables]]
                path = "another"

                [[tables.fields]]
                name = "great-column"
                in_place = false
                cast_type = "utf8-str"
                mode = "encrypted-duplicate"

                [[tables.fields.indexes]]
                version = 1
                kind = "ore"

                [[tables.fields.indexes]]
                version = 1
                kind = "match"
                k = 6
                m = 2048
                include_original = true

                [tables.fields.indexes.tokenizer]
                kind = "ngram"
                token_length = 3

                [[tables.fields.indexes.token_filters]]
                kind = "downcase"
            "#}
        );

        Ok(())
    }

    #[test]
    fn test_sort_indexes() -> Result<(), Box<dyn Error>> {
        let config = DatasetConfig::init()
            .add_table(
                TableConfig::new("users")?.add_column(
                    ColumnConfig::build("name")
                        .add_index(column::Index::new_ore())
                        .add_index(column::Index::new_unique())
                        .add_index(column::Index::new_match()),
                )?,
            )?
            .sort_indexes_by_type();

        let index_types = &config.tables[0].fields[0]
            .indexes
            .iter()
            .map(|index| index.as_str())
            .collect::<Vec<_>>();

        assert_eq!(index_types, &vec!["match", "ore", "unique"]);

        Ok(())
    }
}
