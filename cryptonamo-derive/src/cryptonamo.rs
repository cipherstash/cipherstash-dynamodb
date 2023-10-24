use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{DeriveInput, LitStr, Data, Fields};

struct Settings {
    sort_key_prefix: String,
    partition_key: Option<String>,
    protected_attributes: Vec<String>,
    unprotected_attributes: Vec<String>,
}

impl Settings {
    fn new(sort_key_prefix: String) -> Self {
        Self {
            sort_key_prefix,
            partition_key: None,
            protected_attributes: Vec::new(),
            unprotected_attributes: Vec::new(),
        }
    }

    fn set_sort_key_prefix(&mut self, value: LitStr) -> Result<(), syn::Error> {
        self.sort_key_prefix = value.value();
        Ok(())
    }

    fn set_partition_key(&mut self, value: LitStr) -> Result<(), syn::Error> {
        self.partition_key = Some(value.value());
        Ok(())
    }

    fn get_partition_key(&self) -> Result<String, syn::Error> {
        self.partition_key.clone().ok_or_else(|| syn::Error::new_spanned(
            &self.sort_key_prefix,
            "No partition key defined for this struct",
        ))
    }

    fn add_attribute(&mut self, value: String, will_encrypt: bool) {
        if will_encrypt {
            self.protected_attributes.push(value);
        } else {
            self.unprotected_attributes.push(value);
        }
    }
}

pub(crate) fn derive_cryptonamo(DeriveInput { ident, attrs, data, ..}: DeriveInput) -> Result<TokenStream, syn::Error> {
    let mut settings = Settings::new(ident.to_string().to_lowercase());

    for attr in attrs {
        if attr.path().is_ident("cryptonamo") {
            attr.parse_nested_meta(|meta| {
                let ident = meta.path.get_ident().map(|i| i.to_string());
                match ident.as_deref() {
                    Some("sort_key_prefix") => {
                        let value = meta.value()?;
                        let t: LitStr = value.parse()?;
                        settings.set_sort_key_prefix(t)
                    }
                    Some("partition_key") => {
                        let value = meta.value()?;
                        let t: LitStr = value.parse()?;
                        settings.set_partition_key(t)
                    }
                    _ => Err(meta.error("unsupported attribute")),
                }
            })?;
        }
    }

    // Only support structs
    if let Data::Struct(data_struct) = &data {
        if let Fields::Named(fields_named) = &data_struct.fields {
            for field in &fields_named.named {
                let ident = &field.ident;
                let mut will_encrypt = true;
                let mut skip = false;

                // Parse the meta for the field
                for attr in &field.attrs {
                    if attr.path().is_ident("cryptonamo") {
                        attr.parse_nested_meta(|meta| {
                            let ident = meta.path.get_ident().map(|i| i.to_string());
                            match ident.as_deref() {
                                Some("plaintext") => {
                                    // Don't encrypt this field
                                    will_encrypt = false;
                                    Ok(())
                                }
                                Some("skip") => {
                                    // Don't even store this field
                                    skip = true;
                                    Ok(())
                                }
                                _ => Err(meta.error("unsupported field attribute")),
                            }
                        })?;
                    }
                }

                if !skip {
                    settings.add_attribute(
                        ident
                            .as_ref()
                            .ok_or(syn::Error::new_spanned(&settings.sort_key_prefix, "missing field"))?
                            .to_string(),
                        will_encrypt
                    );
                }
            }
        }
    }

    let partition_key = format_ident!("{}", settings.get_partition_key()?);
    let type_name = settings.sort_key_prefix;

    let protected_impl = settings.protected_attributes.iter().map(|name| {
        let field = format_ident!("{}", name);

        quote! {
            attributes.insert(#name, cryptonamo::Plaintext::from(self.#field.clone()));
        }
    });

    let plaintext_impl = settings.unprotected_attributes.iter().map(|name| {
        let field = format_ident!("{}", name);

        quote! {
            attributes.insert(#name, cryptonamo::Plaintext::from(self.#field.clone()));
        }
    });

    let expanded = quote! {
        impl cryptonamo::traits::Cryptonamo for #ident {
            fn type_name() -> &'static str {
                #type_name
            }

            fn partition_key(&self) -> String {
                self.#partition_key.to_string()
            }
        }

        impl cryptonamo::traits::EncryptedRecord for #ident {
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

    Ok(expanded)
}