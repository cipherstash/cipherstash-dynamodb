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

    let sort_key_prefix = settings.sort_key_prefix.as_ref();

    let type_name = settings.type_name.clone();

    let protected_attributes = settings.protected_attributes();
    let ident = settings.ident();

    let is_partition_key_encrypted = protected_attributes.contains(&partition_key_field.as_str());

    let is_sort_key_encrypted = settings
        .sort_key_field
        .as_ref()
        .map(|x| protected_attributes.contains(&x.as_str()))
        .unwrap_or(true);

    let sort_key_impl = if let Some(sort_key_field) = &settings.sort_key_field {
        let sort_key_attr = format_ident!("{sort_key_field}");

        if let Some(prefix) = sort_key_prefix {
            quote! {
                format!("{}#{}", #prefix, self.#sort_key_attr)
            }
        } else {
            quote! {
                self.#sort_key_attr.to_string()
            }
        }
    } else {
        quote! { #type_name }
    };

    let pk_parts_impl = if is_partition_key_encrypted {
        quote! {
            let pk = cipherstash_dynamodb::crypto::b64_encode(
                cipherstash_dynamodb::crypto::hmac(
                    &pk,
                    None,
                    cipher
                )?
            );
        }
    } else {
        quote! {}
    };

    let sk_parts_impl = if is_sort_key_encrypted {
        quote! {
            let sk = cipherstash_dynamodb::crypto::b64_encode(
                cipherstash_dynamodb::crypto::hmac(
                    &sk,
                    Some(pk.as_str()),
                    cipher
                )?
            );
        }
    } else {
        quote! {}
    };

    let primary_key_impl = if settings.sort_key_field.is_some() {
        quote! { type PrimaryKey = cipherstash_dynamodb::PkSk; }
    } else {
        quote! { type PrimaryKey = cipherstash_dynamodb::Pk; }
    };

    let primary_key_pk_sk_impl = if settings.sort_key_field.is_some() {
        if let Some(sort_key_prefix) = sort_key_prefix {
            quote! {
                let pk = primary_key.0;
                let sk = format!("{}#{}", #sort_key_prefix, primary_key.1);
            }
        } else {
            quote! {
                let pk = primary_key.0;
                let sk = primary_key.1;
            }
        }
    } else {
        quote! {
            let pk = primary_key.0;
            let sk = #type_name.to_string();
        }
    };

    let expanded = quote! {
        impl cipherstash_dynamodb::traits::Identifiable for #ident {
            #primary_key_impl

            fn get_primary_key_parts(
                &self,
                cipher: &cipherstash_dynamodb::traits::Encryption<impl cipherstash_dynamodb::traits::Credentials<Token = cipherstash_dynamodb::traits::ServiceToken>>,
            ) -> Result<cipherstash_dynamodb::traits::PrimaryKeyParts, cipherstash_dynamodb::traits::PrimaryKeyError> {
                let pk = self.#partition_key_attr.to_string();
                let sk = { #sort_key_impl };

                #pk_parts_impl
                #sk_parts_impl

                Ok(cipherstash_dynamodb::traits::PrimaryKeyParts { pk, sk })
            }

            fn get_primary_key_parts_from_key(
                primary_key: Self::PrimaryKey,
                cipher: &cipherstash_dynamodb::traits::Encryption<impl cipherstash_dynamodb::traits::Credentials<Token = cipherstash_dynamodb::traits::ServiceToken>>,
            ) -> Result<cipherstash_dynamodb::traits::PrimaryKeyParts, cipherstash_dynamodb::traits::PrimaryKeyError> {
                #primary_key_pk_sk_impl

                #pk_parts_impl
                #sk_parts_impl

                Ok(cipherstash_dynamodb::traits::PrimaryKeyParts { pk, sk })
            }
        }
    };

    Ok(expanded)
}
