use super::{index_type::IndexType, AttributeMode, Settings};
use proc_macro2::{Ident, Span};
use std::collections::HashMap;
use syn::{Data, DeriveInput, Fields, LitStr};

enum SortKeyPrefix {
    Default,
    Value(String),
    None,
}

impl SortKeyPrefix {
    fn into_prefix(self, default: &str) -> Option<String> {
        match self {
            Self::Default => Some(default.to_string()),
            Self::Value(v) => Some(v),
            Self::None => None,
        }
    }
}

const RESERVED_FIELD_NAMES: &'static [&'static str] = &["term"];

pub(crate) struct SettingsBuilder {
    ident: Ident,
    type_name: String,
    sort_key_prefix: SortKeyPrefix,
    sort_key_field: Option<String>,
    partition_key_field: Option<String>,
    protected_attributes: Vec<String>,
    unprotected_attributes: Vec<String>,
    skipped_attributes: Vec<String>,
    indexes: Vec<IndexType>,
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
            sort_key_prefix: SortKeyPrefix::Default,
            sort_key_field: None,
            partition_key_field: None,
            protected_attributes: Vec::new(),
            unprotected_attributes: Vec::new(),
            skipped_attributes: Vec::new(),
            indexes: Vec::new(),
        }
    }

    pub(crate) fn container_attributes(
        mut self,
        DeriveInput { attrs, .. }: &DeriveInput,
    ) -> Result<Self, syn::Error> {
        for attr in attrs {
            if attr.path().is_ident("cipherstash") {
                attr.parse_nested_meta(|meta| {
                    let ident = meta.path.get_ident().map(|i| i.to_string());
                    match ident.as_deref() {
                        Some("sort_key_prefix") => {
                            let value = meta.value()?;

                            if let Ok(t) = value.parse::<LitStr>() {
                                let v = t.value().to_string();
                                self.set_sort_key_prefix(v)?;
                                return Ok(());
                            }

                            if let Ok(t) = value.parse::<Ident>() {
                                let v = t.to_string();

                                if v == "None" {
                                    self.sort_key_prefix = SortKeyPrefix::None;
                                }
                            }

                            Ok(())
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

                let explicit_pk = all_field_names.contains(&String::from("pk"));
                let explicit_sk = all_field_names.contains(&String::from("sk"));

                let mut compound_indexes: HashMap<String, Vec<(String, String, Span)>> =
                    Default::default();

                for field in &fields_named.named {
                    let ident = &field.ident;
                    let mut attr_mode = AttributeMode::Protected;

                    let field_name = ident
                        .as_ref()
                        .ok_or_else(|| {
                            syn::Error::new_spanned(
                                field,
                                "internal error: identifier was not Some",
                            )
                        })?
                        .to_string();

                    if field_name.starts_with("__") {
                        return Err(syn::Error::new_spanned(
                            field,
                            format!(
                                "Invalid field '{field_name}': fields must not be prefixed with __"
                            ),
                        ));
                    }

                    if RESERVED_FIELD_NAMES.contains(&field_name.as_str()) {
                        return Err(syn::Error::new_spanned(
                            field,
                            format!(
                                "Invalid field '{field_name}': name is reserved for internal use"
                            ),
                        ));
                    }

                    if field_name == "pk" {
                        let has_partition_key_attr = field
                            .attrs
                            .iter()
                            .find(|x| x.path().is_ident("partition_key"))
                            .is_some();

                        if !has_partition_key_attr {
                            return Err(syn::Error::new_spanned(
                                field,
                                format!("field named 'pk' must be annotated with #[partition_key]"),
                            ));
                        }
                    }

                    if field_name == "sk" {
                        let has_partition_key_attr = field
                            .attrs
                            .iter()
                            .find(|x| x.path().is_ident("sort_key"))
                            .is_some();

                        if !has_partition_key_attr {
                            return Err(syn::Error::new_spanned(
                                field,
                                format!("field named 'sk' must be annotated with #[sort_key]"),
                            ));
                        }
                    }

                    // Parse the meta for the field
                    for attr in &field.attrs {
                        if attr.path().is_ident("sort_key") {
                            if explicit_sk && field_name != "sk" {
                                return Err(syn::Error::new_spanned(
                                    field,
                                    format!("field '{field_name}' cannot be used as sort key as struct contains field named 'sk' which must be used")
                                ));
                            }

                            if explicit_sk {
                                // if the 'sk' field is set then there should be no prefix
                                // otherwise when deserialising the sk value would be incorrect
                                self.sort_key_prefix = SortKeyPrefix::None;
                            }

                            if let Some(f) = &self.sort_key_field {
                                return Err(syn::Error::new_spanned(
                                    field,
                                    format!("sort key was already specified to be '{f}'"),
                                ));
                            }

                            self.sort_key_field = Some(field_name.clone());
                        }

                        if attr.path().is_ident("partition_key") {
                            if explicit_pk && field_name != "pk" {
                                return Err(syn::Error::new_spanned(
                                    field,
                                    format!("field '{field_name}' cannot be used as partition key as struct contains field named 'pk' which must be used")
                                ));
                            }

                            if let Some(f) = &self.partition_key_field {
                                return Err(syn::Error::new_spanned(
                                    field,
                                    format!("partition key was already specified to be '{f}'"),
                                ));
                            }

                            self.partition_key_field = Some(field_name.clone());
                        }

                        if attr.path().is_ident("cipherstash") {
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
                                    return Err(syn::Error::new(span,  format!("Compound attribute was specified but no query options were. Specify how this field should be queried with the attribute #[cipherstash(query = <option>, compound = \"{compound_index_name}\")]")));
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
            sort_key_field,
            partition_key_field,
            protected_attributes,
            unprotected_attributes,
            skipped_attributes,
            indexes,
        } = self;

        let sort_key_prefix = sort_key_prefix.into_prefix(&type_name);

        // let partition_key_field = partition_key_field.ok_or_else(|| {
        //     syn::Error::new(
        //         proc_macro2::Span::call_site(),
        //         "Missing required attribute: #[partition_key]",
        //     )
        // })?;

        Ok(Settings {
            ident,
            sort_key_prefix,
            type_name,
            sort_key_field,
            partition_key_field,
            protected_attributes,
            unprotected_attributes,
            skipped_attributes,
            indexes,
        })
    }

    pub(crate) fn set_sort_key_prefix(&mut self, value: String) -> Result<(), syn::Error> {
        self.sort_key_prefix = SortKeyPrefix::Value(value);
        Ok(())
    }

    pub(crate) fn set_partition_key(&mut self, value: String) -> Result<(), syn::Error> {
        self.partition_key_field = Some(value);
        Ok(())
    }

    fn add_attribute(&mut self, value: String, mode: AttributeMode) {
        match mode {
            AttributeMode::Protected => self.protected_attributes.push(value),
            AttributeMode::Plaintext => self.unprotected_attributes.push(value),
            AttributeMode::Skipped => self.skipped_attributes.push(value),
        }
    }

    fn add_index(
        &mut self,
        name: impl Into<String>,
        index_type: &str,
        index_type_span: Span,
    ) -> Result<(), syn::Error> {
        let name: String = name.into();

        Self::validate_index_type(index_type, index_type_span)?;

        let index = IndexType::single(name.clone(), index_type.to_string());

        if self
            .indexes
            .iter()
            .any(|existing_index| existing_index == &index)
        {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("Index '{name}' with type '{index}' has been defined more than once"),
            ));
        }

        self.indexes.push(index);

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
                        "Not all fields were annotated with the #[cipherstash(compound)] attribute. Missing fields: {}",
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
                        "Too many fields were annotated with the #[cipherstash(compound)] attribute. Extra fields: {}",
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

        let mut index = IndexType::Single(field, index_type);

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

        if self
            .indexes
            .iter()
            .any(|existing_index| existing_index == &index)
        {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("Index '{name}' with type '{index}' has been defined more than once"),
            ));
        }

        self.indexes.push(index);

        Ok(())
    }
}
