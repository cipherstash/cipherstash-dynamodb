use proc_macro2::Span;
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

pub(crate) enum AttributeMode {
    Protected,
    Plaintext,
    Skipped,
}

pub(crate) struct Settings {
    pub(crate) sort_key_prefix: String,
    pub(crate) partition_key: Option<String>,
    pub(crate) protected_attributes: Vec<String>,
    pub(crate) unprotected_attributes: Vec<String>,

    /// Skipped attributes are never encrypted by the `DecryptedRecord` trait will
    /// use these to reconstruct the struct via `Default` (like serde).
    pub(crate) skipped_attributes: Vec<String>,
    pub(crate) indexes: HashMap<String, IndexType>,
}

impl Settings {
    pub(crate) fn new(sort_key_prefix: String) -> Self {
        Self {
            sort_key_prefix,
            partition_key: None,
            protected_attributes: Vec::new(),
            unprotected_attributes: Vec::new(),
            skipped_attributes: Vec::new(),
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

    pub(crate) fn add_attribute(&mut self, value: String, mode: AttributeMode) {
        match mode {
            AttributeMode::Protected => self.protected_attributes.push(value),
            AttributeMode::Plaintext => self.unprotected_attributes.push(value),
            AttributeMode::Skipped => self.skipped_attributes.push(value),
        }
    }

    pub(crate) fn add_compound_index(
        &mut self,
        name: String,
        parts: Vec<(String, String, Span)>,
    ) -> Result<(), syn::Error> {
        let name_parts = name.split("#").collect::<Vec<_>>();

        if name_parts.len() > parts.len() {
            let missing_fields = name_parts
                .iter()
                .filter(|x| !parts.iter().find(|(y, _, _)| x == &y).is_some())
                .cloned()
                .collect::<Vec<_>>();

            return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "Not all fields were annotated with the #[cryptonamo(compound)] attribute. Missing fields: {}",
                        missing_fields.join(",")
                    ),
                ));
        }

        if parts.len() > name_parts.len() {
            let extra_fields = parts
                .iter()
                .map(|(x, _, _)| x)
                .filter(|x| !name_parts.iter().find(|y| x == y).is_some())
                .cloned()
                .collect::<Vec<_>>();

            return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "Too many fields were annotated with the #[cryptonamo(compound)] attribute. Extra fields: {}",
                        extra_fields.join(",")
                    ),
                ));
        }

        let mut name_parts_iter = name_parts.into_iter();

        let field = name_parts_iter.next().unwrap();

        let (field, index_type, index_type_span) = parts
            .iter()
            .find(|x| x.0 == field)
            .ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!("Internal error: index was not specified for field \"{field}\""),
                )
            })?
            .clone();

        Self::validate_index_type(index_type.as_str(), index_type_span)?;

        let mut index = IndexType::Compound1 {
            name: name.clone(),
            index: (field, index_type),
        };

        while let Some(field) = name_parts_iter.next() {
            let (field, index_type, index_type_span) = parts
                .iter()
                .find(|x| x.0 == field)
                .ok_or_else(|| {
                    syn::Error::new(
                        Span::call_site(),
                        format!("Internal error: index was not specified for field \"{field}\""),
                    )
                })?
                .clone();

            Self::validate_index_type(index_type.as_str(), index_type_span)?;

            index = index.and(field, index_type)?;
        }

        self.indexes.insert(name, index);

        Ok(())
    }

    fn validate_index_type(index_type: &str, index_type_span: Span) -> Result<(), syn::Error> {
        if !matches!(index_type.as_ref(), "exact" | "prefix") {
            Err(syn::Error::new(
                index_type_span,
                format!("Unsupported index type: {}", index_type),
            ))
        } else {
            Ok(())
        }
    }

    // TODO: Add an IndexOptions enum so we can pass those through as well
    pub(crate) fn add_index(
        &mut self,
        name: impl Into<String>,
        index_type: &str,
        index_type_span: Span,
    ) -> Result<(), syn::Error> {
        let name = name.into();

        Self::validate_index_type(index_type, index_type_span)?;

        self.indexes.insert(
            name.clone(),
            IndexType::single(name, index_type.to_string()),
        );

        Ok(())
    }
}
