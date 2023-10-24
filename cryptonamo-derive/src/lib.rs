extern crate proc_macro2;
extern crate quote;
extern crate syn;

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod cryptonamo;
use cryptonamo::derive_cryptonamo;

#[proc_macro_derive(Cryptonamo, attributes(cryptonamo))]
pub fn derive_cryptonamo_target(input: TokenStream) -> TokenStream {
    derive_cryptonamo(parse_macro_input!(input as DeriveInput))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
    
}
