use crate::settings::{index_type::IndexType, Settings};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::DeriveInput;

pub(crate) fn derive_searchable(input: DeriveInput) -> Result<TokenStream, syn::Error> {
    let settings = Settings::builder(&input)
        .container_attributes(&input)?
        .field_attributes(&input)?
        .build()?;

    let indexes = settings.indexes();
    let protected_index_names = indexes.keys();
    let ident = settings.ident();

    let indexes_impl = indexes.iter().map(|(_, index)| {
        Ok::<_, syn::Error>(match index {
            IndexType::Single(name, index_type) => {
                let index_type = IndexType::type_to_ident(index_type)?;

                quote! {
                    #name => Some(Box::new(cipherstash_dynamodb::encryption::compound_indexer::#index_type::new(vec![])))
                }
            },
            IndexType::Compound2 { name, index: ((_name_left, index_type_left), (_name_right, index_type_right)) } => {
                let left = IndexType::type_to_ident(index_type_left)?;
                let right = IndexType::type_to_ident(index_type_right)?;

                quote! {
                    #name => Some(Box::new(
                        cipherstash_dynamodb::encryption::compound_indexer::CompoundIndex::new(
                            cipherstash_dynamodb::encryption::compound_indexer::#left::new(vec![])
                        ).and(
                            cipherstash_dynamodb::encryption::compound_indexer::#right::new(vec![])
                        )))
                }
            },
            _ => todo!()
        })
    }).collect::<Result<Vec<_>, _>>()?;

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

    let expanded = quote! {
        #[automatically_derived]
        impl cipherstash_dynamodb::traits::Searchable for #ident {
            fn protected_indexes() -> Vec<&'static str> {
                vec![#(#protected_index_names,)*]
            }

            fn index_by_name(name: &str) -> Option<Box<dyn cipherstash_dynamodb::traits::ComposableIndex>> {
                match name {
                    #(#indexes_impl,)*
                    _ => None,
                }
            }

            fn attribute_for_index(&self, index_name: &str) -> Option<cipherstash_dynamodb::traits::ComposablePlaintext> {
                match index_name {
                    #(#attributes_for_index_impl,)*
                    _ => None,
                }
            }
        }
    };

    Ok(expanded)
}
