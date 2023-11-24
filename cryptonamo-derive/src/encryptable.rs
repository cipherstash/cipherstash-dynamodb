use crate::settings::Settings;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::DeriveInput;

pub(crate) fn derive_encryptable(input: DeriveInput) -> Result<TokenStream, syn::Error> {
    let settings = Settings::builder(&input)
        .container_attributes(&input)?
        .field_attributes(&input)?
        .build()?;

    let partition_key_field = settings.get_partition_key()?;
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

    let into_unsealed_impl = protected_attributes
        .iter()
        .map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                .add_protected(#attr, |x| cryptonamo::traits::Plaintext::from(&x.#attr_ident))
            }
        })
        .chain(plaintext_attributes.iter().map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                .add_plaintext(#attr, |x| cryptonamo::traits::TableAttribute::from(&x.#attr_ident))
            }
        }));

    let sort_key_impl = if let Some(sort_key_field) = &settings.sort_key_field {
        let sort_key_attr = format_ident!("{sort_key_field}");

        quote! {
            if let Some(prefix) = Self::sort_key_prefix() {
                format!("{}#{}", prefix, self.#sort_key_attr)
            } else {
                self.#sort_key_attr.clone()
            }
        }
    } else {
        quote! { Self::type_name().into() }
    };

    let primary_key_impl = if settings.sort_key_field.is_some() {
        quote! { type PrimaryKey = cryptonamo::PkSk; }
    } else {
        quote! { type PrimaryKey = cryptonamo::Pk; }
    };

    let expanded = quote! {
        #[automatically_derived]
        impl cryptonamo::traits::Encryptable for #ident {
            #primary_key_impl

            fn type_name() -> &'static str {
                #type_name
            }

            fn sort_key(&self) -> String {
                #sort_key_impl
            }

            fn sort_key_prefix() -> Option<&'static str> {
                #sort_key_prefix
            }

            fn is_partition_key_encrypted() -> bool {
                #is_partition_key_encrypted
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

            fn into_sealer(self) -> Result<cryptonamo::crypto::Sealer<Self>, cryptonamo::crypto::SealError> {
                Ok(cryptonamo::crypto::Sealer::new_with_descriptor(self, Self::type_name())
                    #(#into_unsealed_impl?)*)
            }
        }
    };

    Ok(expanded)
}
