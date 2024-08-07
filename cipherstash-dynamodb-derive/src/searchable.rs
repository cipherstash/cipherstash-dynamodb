use crate::settings::Settings;
use proc_macro2::TokenStream;
use quote::quote;
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
        .map(|index| {
            let index_name = index.index_name();
            let index_type = index.to_cipherstash_dynamodb_type()?;

            Ok::<_, syn::Error>(quote! {
                ( std::borrow::Cow::Borrowed(#index_name), #index_type )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let indexes_impl = indexes
        .iter()
        .map(|index| {
            let index_name = index.index_name();
            let indexer = index.to_cipherstash_dynamodb_indexer()?;
            let index_type = index.to_cipherstash_dynamodb_type()?;

            Ok::<_, syn::Error>(quote! {
                ( #index_name, #index_type ) => Some(#indexer)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let attributes_for_index_impl = indexes
        .iter()
        .map(|index| {
            let index_name = index.index_name();
            let field_access = index.to_compound_plaintext_access()?;
            let index_type = index.to_cipherstash_dynamodb_type()?;

            Ok::<_, syn::Error>(quote! {
                ( #index_name, #index_type ) => #field_access
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let expanded = quote! {
        #[automatically_derived]
        impl cipherstash_dynamodb::traits::Searchable for #ident {
            fn protected_indexes() -> std::borrow::Cow<'static, [( std::borrow::Cow<'static, str>, cipherstash_dynamodb::IndexType )]> {
                std::borrow::Cow::Borrowed(&[#(#protected_indexes_impl,)*])
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
