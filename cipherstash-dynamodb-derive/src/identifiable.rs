use crate::settings::Settings;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::DeriveInput;

pub(crate) fn derive_identifiable(input: DeriveInput) -> Result<TokenStream, syn::Error> {
    let settings = Settings::builder(&input)
        .container_attributes(&input)?
        .field_attributes(&input)?
        .build()?;

    let Some(partition_key_field) = settings.get_partition_key() else {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "Missing required attribute for Identifiable: #[partition_key]",
        ));
    };

    let partition_key_attr = format_ident!("{partition_key_field}");

    let protected_attributes = settings.protected_attributes();
    let ident = settings.ident();

    let is_partition_key_encrypted = protected_attributes.contains(&partition_key_field.as_str());

    let is_sort_key_encrypted = settings
        .sort_key_field
        .as_ref()
        .map(|x| protected_attributes.contains(&x.as_str()))
        .unwrap_or(true);

    let primary_key_impl = if let Some(sort_key_field) = &settings.sort_key_field {
        let sort_key_attr = format_ident!("{sort_key_field}");

        quote! {
            type PrimaryKey = cipherstash_dynamodb::PkSk;

            fn get_primary_key(&self) -> Self::PrimaryKey {
                cipherstash_dynamodb::PkSk(
                    self.#partition_key_attr.to_string(),
                    self.#sort_key_attr.to_string()
                )
            }
        }
    } else {
        quote! {
            type PrimaryKey = cipherstash_dynamodb::Pk;

            fn get_primary_key(&self) -> Self::PrimaryKey {
                cipherstash_dynamodb::Pk(
                    self.#partition_key_attr.to_string()
                )
            }
        }
    };
    let type_name = &settings.type_name;

    let sort_key_prefix_impl = if let Some(prefix) = &settings.sort_key_prefix {
        quote! { Some(std::borrow::Cow::Borrowed(#prefix)) }
    } else {
        quote! { None }
    };

    let expanded = quote! {
        impl cipherstash_dynamodb::traits::Identifiable for #ident {
            #primary_key_impl

            #[inline]
            fn type_name() -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed(#type_name)
            }

            #[inline]
            fn sort_key_prefix() -> Option<std::borrow::Cow<'static, str>> {
                #sort_key_prefix_impl
            }

            fn is_pk_encrypted() -> bool {
                #is_partition_key_encrypted
            }

            fn is_sk_encrypted() -> bool {
                #is_sort_key_encrypted
            }
        }
    };

    Ok(expanded)
}
