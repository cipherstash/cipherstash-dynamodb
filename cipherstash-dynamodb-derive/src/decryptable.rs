use crate::settings::Settings;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::DeriveInput;

pub(crate) fn derive_decryptable(input: DeriveInput) -> Result<TokenStream, syn::Error> {
    let settings = Settings::builder(&input)
        .container_attributes(&input)?
        .field_attributes(&input)?
        .build()?;

    let protected_attributes = settings.protected_attributes();
    let plaintext_attributes = settings.plaintext_attributes();
    let skipped_attributes = settings.skipped_attributes();
    let ident = settings.ident();

    let from_unsealed_impl = protected_attributes
        .iter()
        .map(|(attr, ty)| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                #attr_ident: ::cipherstash_dynamodb::traits::TryFromPlaintext::try_from_plaintext(unsealed.get_protected::<#ty>(#attr))?
            }
        })
        .chain(plaintext_attributes.iter().map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                #attr_ident: ::cipherstash_dynamodb::traits::TryFromTableAttr::try_from_table_attr(unsealed.get_plaintext(#attr))?
            }
        }))
        .chain(skipped_attributes.iter().map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                #attr_ident: Default::default()
            }
        }));

    let expanded = quote! {
        #[automatically_derived]
        impl cipherstash_dynamodb::traits::Decryptable for #ident {
            fn from_unsealed(unsealed: cipherstash_dynamodb::crypto::Unsealed) -> Result<Self, cipherstash_dynamodb::crypto::SealError> {
                Ok(Self {
                    #(#from_unsealed_impl,)*
                })
            }
        }
    };

    Ok(expanded)
}
