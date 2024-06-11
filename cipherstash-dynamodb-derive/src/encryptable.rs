use crate::settings::Settings;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::DeriveInput;

pub(crate) fn derive_encryptable(input: DeriveInput) -> Result<TokenStream, syn::Error> {
    let settings = Settings::builder(&input)
        .container_attributes(&input)?
        .field_attributes(&input)?
        .build()?;

    let partition_key_field = settings.get_partition_key();
    let partition_key = format_ident!("{partition_key_field}");
    let type_name = settings.type_name.clone();

    let sort_key_prefix = settings
        .sort_key_prefix
        .as_ref()
        .map(|x| quote! { Some(#x) })
        .unwrap_or_else(|| quote! { None });

    let protected_attributes = settings.protected_attributes();
    let plaintext_attributes = settings.plaintext_attributes();
    let ident = settings.ident();

    let is_partition_key_encrypted = protected_attributes.contains(&partition_key_field.as_str());
    let is_sort_key_encrypted = settings
        .sort_key_field
        .as_ref()
        .map(|x| protected_attributes.contains(&x.as_str()))
        .unwrap_or(true);

    let into_unsealed_impl = protected_attributes
        .iter()
        .map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                add_protected(#attr, cipherstash_dynamodb::traits::Plaintext::from(self.#attr_ident.to_owned()))
            }
        })
        .chain(plaintext_attributes.iter().map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                add_unprotected(#attr, cipherstash_dynamodb::traits::TableAttribute::from(self.#attr_ident.clone()))
            }
        }));

    let sort_key_impl = if let Some(sort_key_field) = &settings.sort_key_field {
        let sort_key_attr = format_ident!("{sort_key_field}");

        quote! {
            if let Some(prefix) = Self::sort_key_prefix() {
                format!("{}#{}", prefix, self.#sort_key_attr)
            } else {
                self.#sort_key_attr.to_string()
            }
        }
    } else {
        quote! { Self::type_name().into() }
    };

    let primary_key_impl = if settings.sort_key_field.is_some() {
        quote! { type PrimaryKey = cipherstash_dynamodb::PkSk; }
    } else {
        quote! { type PrimaryKey = cipherstash_dynamodb::Pk; }
    };

    let expanded = quote! {
        #[automatically_derived]
        impl cipherstash_dynamodb::traits::Encryptable for #ident {
            #primary_key_impl

            #[inline]
            fn type_name() -> &'static str {
                #type_name
            }

            fn sort_key(&self) -> String {
                #sort_key_impl
            }

            #[inline]
            fn sort_key_prefix() -> Option<&'static str> {
                #sort_key_prefix
            }

            #[inline]
            fn is_partition_key_encrypted() -> bool {
                #is_partition_key_encrypted
            }

            #[inline]
            fn is_sort_key_encrypted() -> bool {
                #is_sort_key_encrypted
            }

            fn partition_key(&self) -> String {
                self.#partition_key.to_string()
            }

            fn protected_attributes() -> Vec<&'static str> {
                vec![#(#protected_attributes,)*]
            }

            fn plaintext_attributes() -> Vec<&'static str> {
                vec![#(#plaintext_attributes,)*]
            }

            fn into_unsealed(self) -> cipherstash_dynamodb::crypto::Unsealed {
                let mut unsealed = cipherstash_dynamodb::crypto::Unsealed::new_with_descriptor(Self::type_name());
                #(unsealed.#into_unsealed_impl;)*

                unsealed
            }
        }
    };

    Ok(expanded)
}
