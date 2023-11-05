extern crate proc_macro2;
extern crate quote;
extern crate syn;

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod cryptonamo;
mod settings;

#[proc_macro_derive(Encryptable, attributes(cryptonamo))]
pub fn derive_encryptable(input: TokenStream) -> TokenStream {
    cryptonamo::derive_encryptable(parse_macro_input!(input as DeriveInput))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[proc_macro_derive(Decryptable, attributes(cryptonamo))]
pub fn derive_decryptable(input: TokenStream) -> TokenStream {
    cryptonamo::derive_decryptable(parse_macro_input!(input as DeriveInput))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
