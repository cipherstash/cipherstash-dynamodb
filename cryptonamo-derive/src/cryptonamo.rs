use crate::settings::{Settings, index_type::IndexType};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::DeriveInput;

pub(crate) fn derive_encryptable(
    input: DeriveInput,
) -> Result<TokenStream, syn::Error> {
    let settings = Settings::builder(&input)
        .container_attributes(&input)?
        .field_attributes(&input)?
        .build()?;

    let partition_key = format_ident!("{}", settings.get_partition_key()?);
    let type_name = settings.sort_key_prefix.to_string();

    let indexes = settings.indexes();
    let protected_index_names = indexes.keys();
    let protected_attributes = settings.protected_attributes();
    let plaintext_attributes = settings.plaintext_attributes();
    let ident = settings.ident();

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
    };

    Ok(expanded)
}


pub(crate) fn derive_decryptable(
    input: DeriveInput,
) -> Result<TokenStream, syn::Error> {
    let settings = Settings::builder(&input)
        .container_attributes(&input)?
        .field_attributes(&input)?
        .build()?;

    let protected_attributes = settings.protected_attributes();
    let plaintext_attributes = settings.plaintext_attributes();
    let skipped_attributes = settings.skipped_attributes();
    let ident = settings.ident();

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
