extern crate proc_macro2;
extern crate quote;
extern crate syn;
use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::quote;
use syn::{parse_macro_input, Attribute, Data, DeriveInput, Fields, Lit, Meta, DataStruct, FieldsNamed};

#[proc_macro_derive(DynamoTarget)] //, attributes(dynamo))]
pub fn derive_dynamo_target(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let dynamo_name = name.to_string().to_lowercase();

    let expanded = quote! {
        use cryptonamo::target::DynamoTarget;

        impl DynamoTarget for #name {
            fn type_name() -> &'static str {
                stringify!(#dynamo_name)
            }
        }
    };

    TokenStream::from(expanded)
}


#[proc_macro_derive(EncryptedRecord, attributes(dynamo))]
pub fn derive_encrypted_record(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let mut partition_key: Option<&Ident> = None;

    let mut field_names = Vec::new();
    let mut field_idents = Vec::new();
    
    // Extract field names and idents from the fields.
    if let Data::Struct(data_struct) = &input.data {
        if let Fields::Named(fields_named) = &data_struct.fields {
            for field in &fields_named.named {
                // Capture the fields
                if let Some(ident) = &field.ident {
                    field_names.push(ident.to_string());
                    field_idents.push(ident);
                }

                    // See if this is the partition key
                    for attr in &field.attrs {
                        if attr.path().is_ident("dynamo") {
                            if let Ok(args) = attr.parse_args::<Ident>() {
                                if args.to_string() == "partition_key" {
                                    // TODO: Check that a partition_key is not already defined
                                    partition_key = field.ident.as_ref();
                                }
                            }
                        }
                    }
            }
        }
    }

    // TODO: Use syn::Error
    if partition_key.is_none() {
        panic!("No partition key defined for {}", name);
    }

    let partition_key_name = partition_key.unwrap();
    
    // Begin generating code for trait implementations.
    let attributes_impl = field_names.iter().zip(field_idents.iter()).map(|(name, ident)| {
        quote! {
            attributes.insert(#name.to_string(), Plaintext::from(self.#ident.to_string()));
        }
    });
    
    // TODO: Define a type for Attributes
    let expanded = quote! {
        use cryptonamo::{enc::EncryptedRecord, Plaintext};
        use std::collections::HashMap;
        // ... other implementations ...
    
        impl EncryptedRecord for #name {
            fn partition_key(&self) -> String {
                self.#partition_key_name.to_string()
            }
    
            fn attributes(&self) -> HashMap<String, Plaintext> {
                let mut attributes = HashMap::new();
                #(#attributes_impl)*
                attributes
            }
        }
    
        // ... other implementations ...
    };
    
    TokenStream::from(expanded)
}
