extern crate proc_macro2;
extern crate quote;
extern crate syn;
use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::{quote, format_ident};
use syn::{parse_macro_input, Data, DeriveInput, Fields, LitStr};

// TODO: Use .unwrap_or_else(syn::Error::into_compile_error) for error handling

#[proc_macro_derive(Cryptonamo, attributes(cryptonamo))]
pub fn derive_dynamo_target(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, attrs, .. } = parse_macro_input!(input as DeriveInput);
    let mut dynamo_name = ident.to_string().to_lowercase();
    let mut partition_key: Option<String> = None;

    for attr in attrs {
        if attr.path().is_ident("cryptonamo") {
            attr.parse_nested_meta(|meta| {
                let ident = meta.path.get_ident().map(|i| i.to_string());
                match ident.as_deref() {
                    Some("sort_key_prefix") => {
                        let value = meta.value()?;
                        let t: LitStr = value.parse()?;
                        dynamo_name = t.value();

                        Ok(())
                    },
                    Some("partition_key") => {
                        let value = meta.value()?;
                        let t: LitStr = value.parse()?;
                        partition_key = Some(t.value());

                        Ok(())
                    },
                    _ => Err(meta.error("unsupported attribute")),
                }
            })
            .unwrap();
        }
    }

    // Validations
    let partition_key = partition_key
        .map(|s| format_ident!("{}", s))
        .unwrap_or_else(|| panic!("No partition key defined for {}", ident));

    let expanded = quote! {
        impl cryptonamo::traits::Cryptonamo for #ident {
            fn type_name() -> &'static str {
                #dynamo_name
            }

            fn partition_key(&self) -> String {
                self.#partition_key.to_string()
            }
        }
    };

    TokenStream::from(expanded)
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
                        }).unwrap() // TODO: Don't unwrap
                    }
                }
                
                record_attributes.push(attribute);
            }
        }
    }

    let (encrypted_attributes, plaintext_attributes): (Vec<(bool, &Ident)>, Vec<(bool, &Ident)>) = record_attributes.into_iter().partition(|(enc, _)| *enc);
    
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
