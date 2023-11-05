use super::{index_type::IndexType, AttributeMode, Settings};
use proc_macro2::{Ident, Span};
use std::collections::HashMap;
use syn::{Data, DeriveInput, Fields, LitStr};

pub(crate) struct SettingsBuilder {
    ident: Ident,
    type_name: String,
    sort_key_prefix: Option<String>,
    partition_key: Option<String>,
    protected_attributes: Vec<String>,
    unprotected_attributes: Vec<String>,
    skipped_attributes: Vec<String>,
    indexes: HashMap<String, IndexType>,
}

impl SettingsBuilder {
    fn validate_index_type(index_type: &str, index_type_span: Span) -> Result<(), syn::Error> {
        if matches!(index_type, "exact" | "prefix") {
            Ok(())
        } else {
            Err(syn::Error::new(
                index_type_span,
                format!("Unsupported index type: {}", index_type),
            ))
        }
    }

    pub(crate) fn new(input: &DeriveInput) -> Self {
        let type_name = input.ident.to_string().to_lowercase();

        Self {
            ident: input.ident.clone(),
            type_name,
            sort_key_prefix: None,
            partition_key: None,
            protected_attributes: Vec::new(),
            unprotected_attributes: Vec::new(),
            skipped_attributes: Vec::new(),
            indexes: HashMap::new(),
        }
    }

    pub(crate) fn container_attributes(
        mut self,
        DeriveInput { attrs, .. }: &DeriveInput,
    ) -> Result<Self, syn::Error> {
        for attr in attrs {
            if attr.path().is_ident("cryptonamo") {
                attr.parse_nested_meta(|meta| {
                    let ident = meta.path.get_ident().map(|i| i.to_string());
                    match ident.as_deref() {
                        Some("sort_key_prefix") => {
                            let value = meta.value()?;
                            let t: LitStr = value.parse()?;
                            let v = t.value().to_string();
                            self.set_sort_key_prefix(v)
                        }
                        Some("partition_key") => {
                            let value = meta.value()?;
                            let t: LitStr = value.parse()?;
                            self.set_partition_key(t.value().to_string())
                        }
                        _ => Err(meta.error("unsupported attribute")),
                    }
                })?;
            }
        }

        Ok(self)
    }

    pub(crate) fn field_attributes(
        mut self,
        DeriveInput { data, .. }: &DeriveInput,
    ) -> Result<Self, syn::Error> {
        // Only support structs
        if let Data::Struct(data_struct) = data {
            if let Fields::Named(fields_named) = &data_struct.fields {
                let all_field_names: Vec<String> = fields_named
                    .named
                    .iter()
                    .flat_map(|x| x.ident.as_ref().map(|x| x.to_string()))
                    .collect();

                let mut compound_indexes: HashMap<String, Vec<(String, String, Span)>> =
                    Default::default();

                for field in &fields_named.named {
                    let ident = &field.ident;
                    let mut attr_mode = AttributeMode::Protected;

                    // Parse the meta for the field
                    for attr in &field.attrs {
                        if attr.path().is_ident("cryptonamo") {
                            let mut query: Option<(String, String, Span)> = None;
                            let mut compound_index_name: Option<(String, Span)> = None;

                            attr.parse_nested_meta(|meta| {
                            let directive = meta.path.get_ident().map(|i| i.to_string());
                            match directive.as_deref() {
                                Some("plaintext") => {
                                    // Don't encrypt this field
                                    attr_mode = AttributeMode::Plaintext;
                                    Ok(())
                                }
                                Some("skip") => {
                                    // Don't even store this field
                                    attr_mode = AttributeMode::Skipped;
                                    Ok(())
                                }
                                Some("query") => {
                                    let value = meta.value()?;
                                    let index_type_span = value.span();
                                    let index_type = value.parse::<LitStr>()?.value();
                                    let index_name = ident
                                        .as_ref()
                                        .ok_or(meta.error("no index type specified"))?
                                        .to_string();

                                    query = Some(( index_name, index_type, index_type_span ));

                                    Ok(())
                                }
                                Some("compound") => {
                                    let value = meta.value()?;

                                    let field_name = ident
                                        .as_ref()
                                        .ok_or(meta.error("no index type specified"))?
                                        .to_string();

                                    let index_name = value.parse::<LitStr>()?.value();

                                    let is_valid_index = index_name
                                        .split('#')
                                        .all(|x| all_field_names.iter().any(|y| y == x));

                                    if !is_valid_index {
                                        return Err(meta.error(format!("Compound index '{index_name}' is not valid. It must be valid fields separated by a '#' character.")));
                                    }

                                    let is_field_mentioned = index_name.split('#')
                                        .any(|x| x == field_name);

                                    if !is_field_mentioned {
                                        return Err(meta.error(format!("Compound index '{index_name}' does not include current field '{field_name}'.")));
                                    }

                                    compound_index_name = Some(( index_name, meta.input.span() ));

                                    Ok(())
                                }
                                _ => Err(meta.error("unsupported field attribute")),
                            }
                        })?;

                            match (query, compound_index_name) {
                                (
                                    Some((index_name, index_type, span)),
                                    Some((compound_index_name, _)),
                                ) => {
                                    compound_indexes
                                        .entry(compound_index_name)
                                        .or_default()
                                        .push((index_name, index_type, span));
                                }

                                (Some((index_name, index_type, span)), None) => {
                                    self.add_index(index_name, index_type.as_ref(), span)?;
                                }

                                (None, Some((compound_index_name, span))) => {
                                    return Err(syn::Error::new(span,  format!("Compound attribute was specified but no query options were. Specify how this field should be queried with the attribute #[cryptonamo(query = <option>, compound = \"{compound_index_name}\")]")));
                                }

                                (None, None) => {}
                            };
                        }
                    }

                    self.add_attribute(
                        ident
                            .as_ref()
                            .ok_or(syn::Error::new_spanned(field, "missing field"))?
                            .to_string(),
                        attr_mode,
                    );
                }

                for (name, parts) in compound_indexes.into_iter() {
                    self.add_compound_index(name, parts)?;
                }
            }
        }

        Ok(self)
    }

    pub(crate) fn build(self) -> Result<Settings, syn::Error> {
        let SettingsBuilder {
            ident,
            type_name,
            sort_key_prefix,
            partition_key,
            protected_attributes,
            unprotected_attributes,
            skipped_attributes,
            indexes,
        } = self;

        let sort_key_prefix = sort_key_prefix.unwrap_or(type_name);

        let partition_key = partition_key.ok_or_else(|| {
            syn::Error::new(
                proc_macro2::Span::call_site(),
                "Missing required attribute: #[cryptonamo(partition_key = \"...\")]",
            )
        })?;

        Ok(Settings {
            ident,
            sort_key_prefix,
            partition_key: Some(partition_key), // TODO: Remove the Some
            protected_attributes,
            unprotected_attributes,
            skipped_attributes,
            indexes,
        })
    }

    pub(crate) fn set_sort_key_prefix(&mut self, value: String) -> Result<(), syn::Error> {
        self.sort_key_prefix = Some(value);
        Ok(())
    }

    pub(crate) fn set_partition_key(&mut self, value: String) -> Result<(), syn::Error> {
        self.partition_key = Some(value);
        Ok(())
    }

    fn add_attribute(&mut self, value: String, mode: AttributeMode) {
        match mode {
            AttributeMode::Protected => self.protected_attributes.push(value),
            AttributeMode::Plaintext => self.unprotected_attributes.push(value),
            AttributeMode::Skipped => self.skipped_attributes.push(value),
        }
    }

    // TODO: Add an IndexOptions enum so we can pass those through as well
    fn add_index(
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

    fn add_compound_index(
        &mut self,
        name: String,
        parts: Vec<(String, String, Span)>,
    ) -> Result<(), syn::Error> {
        let name_parts = name.split('#').collect::<Vec<_>>();

        if name_parts.len() > parts.len() {
            let missing_fields = name_parts
                .iter()
                .filter(|x| parts.iter().any(|(y, _, _)| x == &y))
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
                .filter(|x| name_parts.iter().any(|y| x == y))
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

        for field in name_parts_iter {
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
}
