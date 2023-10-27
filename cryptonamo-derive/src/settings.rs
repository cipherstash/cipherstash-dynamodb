use quote::format_ident;
use std::collections::HashMap;
use syn::LitStr;

#[derive(Clone)]
pub(crate) enum IndexType {
    Single(String, String),
    Compound1 {
        name: String,
        index: (String, String),
    },
    Compound2 {
        name: String,
        index: ((String, String), (String, String)),
    },
    //Compound3 { name: String, index: ((String, String), (String, String), (String, String)) }
}

impl IndexType {
    fn single(name: String, index_type: String) -> Self {
        IndexType::Single(name, index_type)
    }

    fn to_single(self) -> Option<(String, String)> {
        match self {
            IndexType::Single(a, b) => Some((a, b)),
            _ => None,
        }
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
            IndexType::Compound1 { name, index } => Ok(IndexType::Compound2 {
                name: name.to_string(),
                index: (index.clone(), (field, index_type)),
            }),
            // TODO
            /*IndexType::Compound2 { name, index } => {
                Ok(IndexType::Compound3 {
                    name: name.to_string(),
                    index: (index.0, index.1, (field, index_type)),
                })
            },*/
            IndexType::Compound2 { .. } => Err(syn::Error::new_spanned(
                field,
                "Cannot add more than 2 fields to a compound index",
            )),
        }
    }

    pub(crate) fn type_to_ident(index_type: &str) -> Result<syn::Ident, syn::Error> {
        match index_type {
            "exact" => Ok(format_ident!("ExactIndex")),
            "prefix" => Ok(format_ident!("PrefixIndex")),
            _ => Err(syn::Error::new_spanned(
                index_type,
                format!("Unsupported index type: {}", index_type),
            )),
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
        self.partition_key.clone().ok_or_else(|| {
            syn::Error::new_spanned(
                &self.sort_key_prefix,
                "No partition key defined for this struct",
            )
        })
    }

    pub(crate) fn add_attribute(&mut self, value: String, will_encrypt: bool) {
        if will_encrypt {
            self.protected_attributes.push(value);
        } else {
            self.unprotected_attributes.push(value);
        }
    }

    pub(crate) fn add_compound_index(&mut self, name: String) -> Result<(), syn::Error> {
        let mut parts = name.split("#");

        let first = parts.next().ok_or_else(|| {
            syn::Error::new_spanned("", format!("Expected compound index name to have parts"))
        })?;

        let mut index = IndexType::Compound1 {
            name: name.clone(),
            index: self
                .indexes
                .get(first)
                .ok_or_else(|| {
                    syn::Error::new_spanned("", format!("Expected index {first} to exist"))
                })?
                .clone()
                .to_single()
                .ok_or_else(|| {
                    syn::Error::new_spanned(
                        "",
                        format!("Expected index {first} to not be compound index"),
                    )
                })?,
        };

        while let Some(part) = parts.next() {
            let (field, index_type) = self
                .indexes
                .get(part)
                .ok_or_else(|| {
                    syn::Error::new_spanned("", format!("Expected index {part} to exist"))
                })?
                .clone()
                .to_single()
                .ok_or_else(|| {
                    syn::Error::new_spanned(
                        "",
                        format!("Expected index {first} to not be compound index"),
                    )
                })?;

            index = index.and(field, index_type)?;
        }

        self.indexes.insert(name, index);

        Ok(())
    }

    // TODO: Add an IndexOptions enum so we can pass those through as well
    pub(crate) fn add_index(
        &mut self,
        name: impl Into<String>,
        index_type: &str,
    ) -> Result<(), syn::Error> {
        let name: String = name.into();
        match index_type {
            "exact" | "prefix" => self.indexes.insert(
                name.to_string(),
                IndexType::single(name, index_type.to_string()),
            ),
            _ => Err(syn::Error::new_spanned(
                index_type,
                format!("Unsupported index type: {}", index_type),
            ))?,
        };

        Ok(())
    }
}

