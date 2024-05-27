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
    let ident = settings.ident();

    let protected_indexes_impl = indexes
        .iter()
        .map(|(index_name, index_type)| {
            let index_type = index_type.to_cipherstash_dynamodb_type()?;

            Ok::<_, syn::Error>(quote! {
                ( #index_name, #index_type )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let indexes_impl = indexes
        .iter()
        .map(|(index_name, index_type)| {
            let indexer = index_type.to_cipherstash_dynamodb_indexer()?;
            let index_type = index_type.to_cipherstash_dynamodb_type()?;

            Ok::<_, syn::Error>(quote! {
                ( #index_name, #index_type ) => Some(#indexer)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let attributes_for_index_impl = indexes
        .iter()
        .map(|(index_name, index_type)| {
            let field_access = index_type.to_compound_plaintext_access()?;
            let index_type = index_type.to_cipherstash_dynamodb_type()?;

            Ok::<_, syn::Error>(quote! {
                ( #index_name, #index_type ) => #field_access
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let expanded = quote! {
        #[automatically_derived]
        impl cipherstash_dynamodb::traits::Searchable for #ident {
            fn protected_indexes() -> Vec<( &'static str, cipherstash_dynamodb::IndexType )> {
                vec![#(#protected_indexes_impl,)*]
            }

            fn index_by_name(index_name: &str, index_type: cipherstash_dynamodb::IndexType) -> Option<Box<dyn cipherstash_dynamodb::traits::ComposableIndex>> {
                match ( index_name, index_type ) {
                    #(#indexes_impl,)*
                    _ => None,
                }
            }

            fn attribute_for_index(&self, index_name: &str, index_type: cipherstash_dynamodb::IndexType) -> Option<cipherstash_dynamodb::traits::ComposablePlaintext> {
                match ( index_name, index_type ) {
                    #(#attributes_for_index_impl,)*
                    _ => None,
                }
            }
        }
    };

    Ok(expanded)
}
