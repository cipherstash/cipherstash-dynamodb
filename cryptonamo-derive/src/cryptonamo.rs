use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{DeriveInput, LitStr};

struct Settings {
    sort_key_prefix: String,
    partition_key: Option<String>,
}

impl Settings {
    fn new(sort_key_prefix: String) -> Self {
        Self {
            sort_key_prefix,
            partition_key: None,
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
}

pub(crate) fn derive_cryptonamo(DeriveInput { ident, attrs, ..}: DeriveInput) -> Result<TokenStream, syn::Error> {
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

    let partition_key = format_ident!("{}", settings.get_partition_key()?);
    let type_name = settings.sort_key_prefix;

    let expanded = quote! {
        impl cryptonamo::traits::Cryptonamo for #ident {
            fn type_name() -> &'static str {
                #type_name
            }

            fn partition_key(&self) -> String {
                self.#partition_key.to_string()
            }
        }
    };

    Ok(expanded)
}