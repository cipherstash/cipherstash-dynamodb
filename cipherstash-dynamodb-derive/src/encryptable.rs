use crate::settings::Settings;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::DeriveInput;

pub(crate) fn derive_encryptable(input: DeriveInput) -> Result<TokenStream, syn::Error> {
    let settings = Settings::builder(&input)
        .container_attributes(&input)?
        .field_attributes(&input)?
        .build()?;

    let type_name = settings.type_name.clone();

    let sort_key_prefix_impl = if let Some(prefix) = &settings.sort_key_prefix {
        quote! { Some(#prefix) }
    } else {
        quote! { None }
    };

    let protected_attributes = settings.protected_attributes();
    let plaintext_attributes = settings.plaintext_attributes();
    let ident = settings.ident();

    let into_unsealed_impl = protected_attributes
        .iter()
        .map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                .add_protected(#attr, |x| cipherstash_dynamodb::traits::Plaintext::from(x.#attr_ident.to_owned()))
            }
        })
        .chain(plaintext_attributes.iter().map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                .add_plaintext(#attr, |x| cipherstash_dynamodb::traits::TableAttribute::from(x.#attr_ident.clone()))
            }
        }));

    let expanded = quote! {
        #[automatically_derived]
        impl cipherstash_dynamodb::traits::Encryptable for #ident {
            #[inline]
            fn type_name() -> &'static str {
                #type_name
            }

            #[inline]
            fn sort_key_prefix() -> Option<&'static str> {
                #sort_key_prefix_impl
            }

            fn protected_attributes() -> Vec<&'static str> {
                vec![#(#protected_attributes,)*]
            }

            fn plaintext_attributes() -> Vec<&'static str> {
                vec![#(#plaintext_attributes,)*]
            }

            #[allow(clippy::needless_question_mark)]
            fn into_sealer(self) -> Result<cipherstash_dynamodb::crypto::Sealer<Self>, cipherstash_dynamodb::crypto::SealError> {
                Ok(cipherstash_dynamodb::crypto::Sealer::new_with_descriptor(self, <Self as cipherstash_dynamodb::traits::Encryptable>::type_name())
                    #(#into_unsealed_impl?)*)
            }
        }
    };

    Ok(expanded)
}
