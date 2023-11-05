extern crate proc_macro2;
extern crate quote;
extern crate syn;

mod decryptable;
mod encryptable;
mod searchable;
mod settings;

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(Encryptable, attributes(cryptonamo))]
pub fn derive_encryptable(input: TokenStream) -> TokenStream {
    encryptable::derive_encryptable(parse_macro_input!(input as DeriveInput))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[proc_macro_derive(Decryptable, attributes(cryptonamo))]
pub fn derive_decryptable(input: TokenStream) -> TokenStream {
    decryptable::derive_decryptable(parse_macro_input!(input as DeriveInput))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[proc_macro_derive(Searchable, attributes(cryptonamo))]
pub fn derive_searchable(input: TokenStream) -> TokenStream {
    searchable::derive_searchable(parse_macro_input!(input as DeriveInput))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
