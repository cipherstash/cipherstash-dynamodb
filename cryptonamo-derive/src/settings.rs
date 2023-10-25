use std::collections::HashMap;
use quote::format_ident;
use syn::LitStr;

pub(crate) enum IndexType {
    Single(String, String),
    Compound1 { name: String, index: (String, String) },
    Compound2 { name: String, index: ((String, String), (String, String)) },
    //Compound3 { name: String, index: ((String, String), (String, String), (String, String)) }
}

impl IndexType {
    fn single(name: String, index_type: String) -> Self {
        IndexType::Single(name, index_type)
    }

    fn compound(compound_name: String, field_name: String, index_type: String) -> Self {
        IndexType::Compound1 {
            name: compound_name,
            index: (field_name, index_type),
        }
    }

    fn and(self, field: String, index_type: String) -> Result<Self, syn::Error> {
        match self {
            IndexType::Single(_, _) => unimplemented!(),
            IndexType::Compound1 { name, index } => {
                Ok(IndexType::Compound2 {
                    name: name.to_string(),
                    index: (index.clone(), (field, index_type)),
                })
            },
            // TODO
            /*IndexType::Compound2 { name, index } => {
                Ok(IndexType::Compound3 {
                    name: name.to_string(),
                    index: (index.0, index.1, (field, index_type)),
                })
            },*/
            IndexType::Compound2 { .. } => {
                Err(syn::Error::new_spanned(field, "Cannot add more than 2 fields to a compound index"))
            }
        }
    }

    pub(crate) fn type_to_ident(index_type: &str) -> Result<syn::Ident, syn::Error> {
        match index_type {
            "exact" => Ok(format_ident!("ExactIndex")),
            "prefix" => Ok(format_ident!("PrefixIndex")),
            _ => Err(syn::Error::new_spanned(
                index_type,
                format!("Unsupported index type: {}", index_type),
            ))
        }
    }
}

pub(crate) struct Settings {
    pub(crate) sort_key_prefix: String,
    pub(crate) partition_key: Option<String>,
    pub(crate) protected_attributes: Vec<String>,
    pub(crate) unprotected_attributes: Vec<String>,
    pub(crate) indexes: HashMap<String, IndexType>,
}

impl Settings {
    pub(crate) fn new(sort_key_prefix: String) -> Self {
        Self {
            sort_key_prefix,
            partition_key: None,
            protected_attributes: Vec::new(),
            unprotected_attributes: Vec::new(),
            indexes: HashMap::new(),
        }
    }

    pub(crate) fn set_sort_key_prefix(&mut self, value: LitStr) -> Result<(), syn::Error> {
        self.sort_key_prefix = value.value();
        Ok(())
    }

    pub(crate) fn set_partition_key(&mut self, value: LitStr) -> Result<(), syn::Error> {
        self.partition_key = Some(value.value());
        Ok(())
    }

    pub(crate) fn get_partition_key(&self) -> Result<String, syn::Error> {
        self.partition_key.clone().ok_or_else(|| syn::Error::new_spanned(
            &self.sort_key_prefix,
            "No partition key defined for this struct",
        ))
    }

    pub(crate) fn add_attribute(&mut self, value: String, will_encrypt: bool) {
        if will_encrypt {
            self.protected_attributes.push(value);
        } else {
            self.unprotected_attributes.push(value);
        }
    }

    // TODO: Add an IndexOptions enum so we can pass those through as well
    pub(crate) fn add_index(&mut self, name: impl Into<String>, index_type: &str, compound_name: Option<impl Into<String>>) -> Result<(), syn::Error> {
        if let Some(compound_name) = compound_name {
            self.add_or_compose_index(compound_name, name, index_type)?;
            return Ok(());
        }
        let name: String = name.into();
        match index_type {
            "exact" | "prefix" => self.indexes.insert(name.to_string(), IndexType::single(name, index_type.to_string())),
            _ => Err(syn::Error::new_spanned(
                index_type,
                format!("Unsupported index type: {}", index_type),
            ))?
        };

        Ok(())
    }

    pub(crate) fn add_or_compose_index(&mut self, compound_name: impl Into<String>, field_name: impl Into<String>, index_type: &str) -> Result<(), syn::Error> {
        let compound_name: String = compound_name.into();
        let field_name: String = field_name.into();

        match index_type {
            "exact" | "prefix" => {
                if let Some(index) = self.indexes.remove(&compound_name) {
                    self.indexes.insert(compound_name.to_string(), index.and(field_name.to_string(), index_type.to_string())?);
                } else {
                    self.indexes.insert(compound_name.to_string(), IndexType::compound(compound_name, field_name, index_type.to_string()));
                }
            },
            _ => Err(syn::Error::new_spanned(
                index_type,
                format!("Unsupported index type: {}", index_type),
            ))?
        };

        Ok(())
    }
}