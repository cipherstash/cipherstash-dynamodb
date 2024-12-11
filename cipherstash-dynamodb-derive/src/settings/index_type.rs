use std::fmt::Display;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

#[derive(Clone, PartialEq)]
pub(crate) enum IndexType {
    Single(String, String),
    Compound2((String, String), (String, String)),
}

impl Display for IndexType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single(_field, index_type) => f.write_str(index_type),
            Self::Compound2((_field_a, index_type_a), (_field_b, index_type_b)) => {
                f.write_str(format!("{index_type_a}:{index_type_b}").as_str())
            }
        }
    }
}

impl IndexType {
    pub(super) fn single(name: String, index_type: String) -> Self {
        IndexType::Single(name, index_type)
    }

    pub(super) fn and(self, field: String, index_type: String) -> Result<Self, syn::Error> {
        match self {
            IndexType::Single(field_a, index_a) => Ok(IndexType::Compound2(
                (field_a, index_a),
                (field, index_type),
            )),
            IndexType::Compound2(..) => Err(syn::Error::new_spanned(
                field,
                "Cannot add more than 2 fields to a compound index",
            )),
        }
    }

    pub fn index_name(&self) -> String {
        match self {
            Self::Single(field, _) => field.clone(),
            Self::Compound2((field_a, _), (field_b, _)) => format!("{field_a}#{field_b}"),
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

    pub(crate) fn type_to_cipherstash_dynamodb_type(
        index_type: &str,
    ) -> Result<TokenStream, syn::Error> {
        match index_type {
            "exact" => Ok(quote! {
                cipherstash_dynamodb::SingleIndex::Exact
            }),
            "prefix" => Ok(quote! {
                cipherstash_dynamodb::SingleIndex::Prefix
            }),
            _ => Err(syn::Error::new_spanned(
                index_type,
                format!("Unsupported index type: {}", index_type),
            )),
        }
    }

    pub(crate) fn to_compound_plaintext_access(&self) -> Result<TokenStream, syn::Error> {
        match self {
            Self::Single(field, _) => {
                let field = format_ident!("{field}");

                Ok(quote! {
                    self.#field.clone().try_into().ok()
                })
            }

            Self::Compound2((field_a, _), (field_b, _)) => {
                let field_a = format_ident!("{field_a}");
                let field_b = format_ident!("{field_b}");

                Ok(quote! {
                    ( self.#field_a.clone(), self.#field_b.clone() ).try_into().ok()
                })
            }
        }
    }

    pub(crate) fn to_cipherstash_dynamodb_indexer(&self) -> Result<TokenStream, syn::Error> {
        match self {
            Self::Single(_, index_type) => {
                let index_type = Self::type_to_ident(index_type)?;

                Ok(quote! {
                    Box::new(cipherstash_dynamodb::encryption::compound_indexer::#index_type::default())
                })
            }

            Self::Compound2((_field_a, index_a), (_field_b, index_b)) => {
                let index_a = Self::type_to_ident(index_a)?;
                let index_b = Self::type_to_ident(index_b)?;

                Ok(quote! {
                    Box::new(
                        cipherstash_dynamodb::encryption::compound_indexer::CompoundIndex::new(
                            cipherstash_dynamodb::encryption::compound_indexer::#index_a::default()
                        ).and(
                            cipherstash_dynamodb::encryption::compound_indexer::#index_b::default()
                        ))
                })
            }
        }
    }

    pub(crate) fn to_cipherstash_dynamodb_type(&self) -> Result<TokenStream, syn::Error> {
        match self {
            Self::Single(_, index_type) => {
                let index_type = Self::type_to_cipherstash_dynamodb_type(index_type)?;

                Ok(quote! {
                    cipherstash_dynamodb::IndexType::Single(#index_type)
                })
            }

            Self::Compound2((_field_a, index_a), (_field_b, index_b)) => {
                let index_type_a = Self::type_to_cipherstash_dynamodb_type(index_a)?;
                let index_type_b = Self::type_to_cipherstash_dynamodb_type(index_b)?;

                Ok(quote! {
                    cipherstash_dynamodb::IndexType::Compound2(
                        ( #index_type_a, #index_type_b )
                    )
                })
            }
        }
    }
}
