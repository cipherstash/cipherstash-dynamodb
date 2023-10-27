use std::collections::HashSet;

use crate::settings::{IndexType, Settings};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
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

            let mut compound_indexes = HashSet::<String>::new();

            for field in &fields_named.named {
                let ident = &field.ident;
                let mut will_encrypt = true;
                let mut skip = false;

                // Parse the meta for the field
                for attr in &field.attrs {
                    if attr.path().is_ident("cryptonamo") {
                        attr.parse_nested_meta(|meta| {
                            let directive = meta.path.get_ident().map(|i| i.to_string());
                            match directive.as_deref() {
                                Some("plaintext") => {
                                    // Don't encrypt this field
                                    will_encrypt = false;
                                    Ok(())
                                }
                                Some("skip") => {
                                    // Don't even store this field
                                    skip = true;
                                    Ok(())
                                }
                                Some("query") => {
                                    let value = meta.value()?;
                                    let index_type = value.parse::<LitStr>()?.value();
                                    let index_name = ident
                                        .as_ref()
                                        .ok_or(meta.error("no index type specified"))?
                                        .to_string();

                                    settings.add_index(index_name, index_type.as_ref())?;

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

                                    compound_indexes.insert(index_name);

                                    Ok(())
                                }
                                _ => Err(meta.error("unsupported field attribute")),
                            }
                        })?;
                    }
                }

                if !skip {
                    settings.add_attribute(
                        ident
                            .as_ref()
                            .ok_or(syn::Error::new_spanned(
                                &settings.sort_key_prefix,
                                "missing field",
                            ))?
                            .to_string(),
                        will_encrypt,
                    );
                }
            }

            for index in compound_indexes.into_iter() {
                settings.add_compound_index(index)?;
            }
        }
    }

    let partition_key = format_ident!("{}", settings.get_partition_key()?);
    let type_name = settings.sort_key_prefix;

    let protected_impl = settings.protected_attributes.iter().map(|name| {
        let field = format_ident!("{}", name);

        quote! {
            attributes.insert(#name, cryptonamo::Plaintext::from(self.#field.clone()));
        }
    });

    let plaintext_impl = settings.unprotected_attributes.iter().map(|name| {
        let field = format_ident!("{}", name);

        quote! {
            attributes.insert(#name, cryptonamo::Plaintext::from(self.#field.clone()));
        }
    });

    let protected_index_names = settings.indexes.keys();

    let indexes_impl = settings.indexes.iter().map(|(_, index)| {
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

    let attributes_for_index_impl = settings.indexes.iter().map(|(_, index)| match index {
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

    let expanded = quote! {
        impl cryptonamo::traits::Cryptonamo for #ident {
            fn type_name() -> &'static str {
                #type_name
            }

            fn partition_key(&self) -> String {
                self.#partition_key.to_string()
            }
        }

        impl cryptonamo::traits::EncryptedRecord for #ident {
            fn protected_attributes(&self) -> std::collections::HashMap<&'static str, cryptonamo::Plaintext> {
                let mut attributes = std::collections::HashMap::new();
                #(#protected_impl)*
                attributes
            }

            fn plaintext_attributes(&self) -> std::collections::HashMap<&'static str, cryptonamo::Plaintext> {
                let mut attributes = std::collections::HashMap::new();
                #(#plaintext_impl)*
                attributes
            }
        }

        impl cryptonamo::traits::SearchableRecord for #ident {
            fn protected_indexes() -> Vec<&'static str> {
                vec![#(#protected_index_names,)*]
            }

            fn index_by_name(name: &str) -> Option<Box<dyn cryptonamo::ComposableIndex>> {
                use cipherstash_client::encryption::compound_indexer::*;
                match name {
                    #(#indexes_impl,)*
                    _ => None,
                }
            }

            fn attribute_for_index(&self, index_name: &str) -> Option<cryptonamo::ComposablePlaintext> {
                match index_name {
                    #(#attributes_for_index_impl,)*
                    _ => None,
                }
            }
        }
    };

    Ok(expanded)
}

