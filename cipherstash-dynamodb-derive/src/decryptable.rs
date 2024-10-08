use crate::settings::Settings;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::DeriveInput;

pub(crate) fn derive_decryptable(input: DeriveInput) -> Result<TokenStream, syn::Error> {
    let settings = Settings::builder(&input)
        .container_attributes(&input)?
        .field_attributes(&input)?
        .build()?;

    let protected_excluding_handlers = settings.protected_attributes_excluding_handlers();
    let plaintext_attributes = settings.plaintext_attributes();

    let protected_attributes_cow = settings
        .protected_attributes()
        .into_iter()
        .map(|x| quote! { std::borrow::Cow::Borrowed(#x) });

    let plaintext_attributes_cow = settings
        .plaintext_attributes()
        .into_iter()
        .map(|x| quote! { std::borrow::Cow::Borrowed(#x) });

    let skipped_attributes = settings.skipped_attributes();
    let ident = settings.ident();

    let from_unsealed_impl = protected_excluding_handlers
        .iter()
        .map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                #attr_ident: ::cipherstash_dynamodb::traits::TryFromPlaintext::try_from_optional_plaintext(unsealed.take_protected(#attr))?
            }
        })
        .chain(plaintext_attributes.iter().map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                #attr_ident: ::cipherstash_dynamodb::traits::TryFromTableAttr::try_from_table_attr(unsealed.take_unprotected(#attr))?
            }
        }))
        .chain(skipped_attributes.iter().map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                #attr_ident: Default::default()
            }
        }))
        .chain(settings.decrypt_handlers().iter().map(|(attr, handler)| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                #attr_ident: #handler(&mut unsealed)?
            }
        }));

    let expanded = quote! {
        #[automatically_derived]
        impl cipherstash_dynamodb::traits::Decryptable for #ident {
            fn protected_attributes() -> std::borrow::Cow<'static, [std::borrow::Cow<'static, str>]> {
                std::borrow::Cow::Borrowed(&[#(#protected_attributes_cow,)*])
            }

            fn plaintext_attributes() -> std::borrow::Cow<'static, [std::borrow::Cow<'static, str>]> {
                std::borrow::Cow::Borrowed(&[#(#plaintext_attributes_cow,)*])
            }

            fn from_unsealed(mut unsealed: cipherstash_dynamodb::crypto::Unsealed) -> Result<Self, cipherstash_dynamodb::crypto::SealError> {
                Ok(Self {
                    #(#from_unsealed_impl,)*
                })
            }
        }
    };

    Ok(expanded)
}
