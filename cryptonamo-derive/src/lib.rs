extern crate proc_macro2;
extern crate quote;
extern crate syn;

use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::{quote};
use syn::{parse_macro_input, Data, DeriveInput, Fields};

mod cryptonamo;
use cryptonamo::derive_cryptonamo;

// TODO: Use .unwrap_or_else(syn::Error::into_compile_error) for error handling

#[proc_macro_derive(Cryptonamo, attributes(cryptonamo))]
pub fn derive_cryptonamo_target(input: TokenStream) -> TokenStream {
    derive_cryptonamo(parse_macro_input!(input as DeriveInput))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
    
}

// TODO: Do this all in the Cryptonamo derive
#[proc_macro_derive(EncryptedRecord, attributes(dynamo))]
pub fn derive_encrypted_record(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let mut record_attributes: Vec<(bool, &Ident)> = Vec::new();

    // Extract field names and idents from the fields.
    if let Data::Struct(data_struct) = &input.data {
        if let Fields::Named(fields_named) = &data_struct.fields {
            for field in &fields_named.named {
                let ident = &field.ident;

                // True indicates that the field will be encrypted
                let mut attribute = (true, ident.as_ref().unwrap()); // TODO: Handle error

                // Parse the meta for the field
                for attr in &field.attrs {
                    if attr.path().is_ident("cryptonamo") {
                        attr.parse_nested_meta(|meta| {
                            if meta.path.is_ident("plaintext") {
                                // Don't encrypt this field
                                attribute.0 = false;
                                Ok(())
                            } else {
                                Err(meta.error("unsupported field attribute"))
                            }
                        })
                        .unwrap() // TODO: Don't unwrap
                    }
                }

                record_attributes.push(attribute);
            }
        }
    }

    let (encrypted_attributes, plaintext_attributes): (Vec<(bool, &Ident)>, Vec<(bool, &Ident)>) =
        record_attributes.into_iter().partition(|(enc, _)| *enc);

    let protected_impl = encrypted_attributes.iter().map(|(_, name)| {
        quote! {
            attributes.insert(stringify!(#name), cryptonamo::Plaintext::from(self.#name.clone()));
        }
    });

    let plaintext_impl = plaintext_attributes.iter().map(|(_, name)| {
        quote! {
            attributes.insert(stringify!(#name), cryptonamo::Plaintext::from(self.#name.clone()));
        }
    });

    let expanded = quote! {
        impl cryptonamo::traits::EncryptedRecord for #name {
            fn protected_attributes(&self) -> std::collections::HashMap<&'static str, cryptonamo::Plaintext> {
                let mut attributes = HashMap::new();
                #(#protected_impl)*
                attributes
            }

            fn plaintext_attributes(&self) -> std::collections::HashMap<&'static str, cryptonamo::Plaintext> {
                let mut attributes = HashMap::new();
                #(#plaintext_impl)*
                attributes
            }
        }
    };

    TokenStream::from(expanded)
}
