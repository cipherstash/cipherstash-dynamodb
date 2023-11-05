use crate::settings::{AttributeMode, IndexType, Settings};
use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use std::collections::HashMap;
use syn::{Data, DeriveInput, Fields, LitStr};

pub(crate) fn derive_cryptonamo(
    DeriveInput {
        ident, attrs, data, ..
    }: DeriveInput,
) -> Result<TokenStream, syn::Error> {
    let mut settings = Settings::new(ident.to_string().to_lowercase());

    for attr in attrs {
        if attr.path().is_ident("cryptonamo") {
            attr.parse_nested_meta(|meta| {
                let ident = meta.path.get_ident().map(|i| i.to_string());
                match ident.as_deref() {
                    Some("sort_key_prefix") => {
                        let value = meta.value()?;
                        let t: LitStr = value.parse()?;
                        settings.set_sort_key_prefix(t)
                    }
                    Some("partition_key") => {
                        let value = meta.value()?;
                        let t: LitStr = value.parse()?;
                        settings.set_partition_key(t)
                    }
                    _ => Err(meta.error("unsupported attribute")),
                }
            })?;
        }
    }

    // Only support structs
    if let Data::Struct(data_struct) = &data {
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
                                        .split("#")
                                        .all(|x| all_field_names.iter().any(|y| y == x));

                                    if !is_valid_index {
                                        return Err(meta.error(format!("Compound index '{index_name}' is not valid. It must be valid fields separated by a '#' character.")));
                                    }

                                    let is_field_mentioned = index_name.split("#")
                                        .any(|x| x == &field_name);

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
                                settings.add_index(index_name, index_type.as_ref(), span)?;
                            }

                            (None, Some((compound_index_name, span))) => {
                                return Err(syn::Error::new(span,  format!("Compound attribute was specified but no query options were. Specify how this field should be queried with the attribute #[cryptonamo(query = <option>, compound = \"{compound_index_name}\")]")));
                            }

                            (None, None) => {}
                        };
                    }
                }

                settings.add_attribute(
                    ident
                        .as_ref()
                        .ok_or(syn::Error::new_spanned(
                            &settings.sort_key_prefix,
                            "missing field",
                        ))?
                        .to_string(),
                    attr_mode,
                );
            }

            for (name, parts) in compound_indexes.into_iter() {
                settings.add_compound_index(name, parts)?;
            }
        }
    }

    // TODO: This is getting a bit unwieldy - split it out into separate functions
    let partition_key = format_ident!("{}", settings.get_partition_key()?);
    let type_name = settings.sort_key_prefix.to_string();

    let indexes = settings.indexes();
    let protected_index_names = indexes.keys();
    let protected_attributes = settings.protected_attributes();
    let plaintext_attributes = settings.plaintext_attributes();
    let skipped_attributes = settings.skipped_attributes();

    let indexes_impl = indexes.iter().map(|(_, index)| {
        match index {
            IndexType::Single(name, index_type) => {
                let index_type = IndexType::type_to_ident(index_type).unwrap();

                quote! {
                    #name => Some(Box::new(cipherstash_client::encryption::compound_indexer::#index_type::new(#name, vec![])))
                }
            },
            IndexType::Compound2 { name, index: ((a, b), (c, d)) } => {
                quote! {
                    #name => Some(((#a.to_string(), #b.to_string()), (#c.to_string(), #d.to_string())).into())
                }
            },
            _ => todo!()
        }
    });

    let attributes_for_index_impl = indexes.iter().map(|(_, index)| match index {
        IndexType::Single(name, _) => {
            let field = format_ident!("{}", name);

            quote! {
                #name => self.#field.clone().try_into().ok()
            }
        }
        IndexType::Compound1 {
            name,
            index: (a, _),
        } => {
            let field = format_ident!("{}", a);

            quote! {
                #name => self.#field.clone().try_into().ok()
            }
        }
        IndexType::Compound2 {
            name,
            index: ((a, _), (b, _)),
        } => {
            let field_a = format_ident!("{}", a);
            let field_b = format_ident!("{}", b);

            quote! {
                #name => {
                    (self.#field_a.clone(), self.#field_b.clone()).try_into().ok()
                }
            }
        }
    });

    let into_unsealed_impl = protected_attributes
        .iter()
        .map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                .add_protected(#attr, |x| cryptonamo::traits::Plaintext::from(&x.#attr_ident))
            }
        })
        .chain(plaintext_attributes.iter().map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                .add_plaintext(#attr, |x| cryptonamo::traits::TableAttribute::from(&x.#attr_ident))
            }
        }));

    let from_unsealed_impl = protected_attributes
        .iter()
        .map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                #attr_ident: unsealed.from_protected(#attr)?.try_into()?
            }
        })
        .chain(plaintext_attributes.iter().map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                #attr_ident: unsealed.from_plaintext(#attr)?.try_into()?
            }
        }))
        .chain(skipped_attributes.iter().map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                #attr_ident: Default::default()
            }
        }));

    let expanded = quote! {
        #[automatically_derived]
        impl cryptonamo::traits::Encryptable for #ident {
            fn type_name() -> &'static str {
                #type_name
            }

            fn partition_key(&self) -> String {
                self.#partition_key.to_string()
            }

            fn protected_attributes() -> Vec<&'static str> {
                vec![#(#protected_attributes,)*]
            }

            fn plaintext_attributes() -> Vec<&'static str> {
                vec![#(#plaintext_attributes,)*]
            }

            fn into_sealer(self) -> Result<cryptonamo::crypto::Sealer<Self>, cryptonamo::crypto::SealError> {
                Ok(cryptonamo::crypto::Sealer::new_with_descriptor(self, Self::type_name())
                    #(#into_unsealed_impl?)*)
            }
        }

        #[automatically_derived]
        impl cryptonamo::traits::Searchable for #ident {
            fn protected_indexes() -> Vec<&'static str> {
                vec![#(#protected_index_names,)*]
            }

            fn index_by_name(name: &str) -> Option<Box<dyn cryptonamo::traits::ComposableIndex>> {
                use cipherstash_client::encryption::compound_indexer::*;
                match name {
                    #(#indexes_impl,)*
                    _ => None,
                }
            }

            fn attribute_for_index(&self, index_name: &str) -> Option<cryptonamo::traits::ComposablePlaintext> {
                match index_name {
                    #(#attributes_for_index_impl,)*
                    _ => None,
                }
            }
        }

        #[automatically_derived]
        impl cryptonamo::traits::Decryptable for #ident {
            fn from_unsealed(unsealed: cryptonamo::crypto::Unsealed) -> Result<Self, cryptonamo::crypto::SealError> {
                Ok(Self {
                    #(#from_unsealed_impl,)*
                })
            }
        }
    };

    Ok(expanded)
}
