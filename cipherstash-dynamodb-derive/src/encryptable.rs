use crate::settings::Settings;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::DeriveInput;

pub(crate) fn derive_encryptable(input: DeriveInput) -> Result<TokenStream, syn::Error> {
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

    let ident = settings.ident();

    let into_unsealed_impl = protected_excluding_handlers
        .iter()
        .map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                unsealed.add_protected(#attr, self.#attr_ident);
            }
        })
        .chain(plaintext_attributes.iter().map(|attr| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                unsealed.add_unprotected(#attr, self.#attr_ident);
            }
        }))
        .chain(settings.encrypt_handlers().iter().map(|(attr, handler)| {
            let attr_ident = format_ident!("{attr}");

            quote! {
                #handler(&mut unsealed, self.#attr_ident);
            }
        }));

    let expanded = quote! {
        #[automatically_derived]
        impl cipherstash_dynamodb::traits::Encryptable for #ident {
            fn protected_attributes() -> std::borrow::Cow<'static, [std::borrow::Cow<'static, str>]> {
                std::borrow::Cow::Borrowed(&[#(#protected_attributes_cow,)*])
            }

            fn plaintext_attributes() -> std::borrow::Cow<'static, [std::borrow::Cow<'static, str>]> {
                std::borrow::Cow::Borrowed(&[#(#plaintext_attributes_cow,)*])
            }

            #[allow(clippy::needless_question_mark)]
            fn into_unsealed(self) -> cipherstash_dynamodb::crypto::Unsealed {
                let mut unsealed = cipherstash_dynamodb::crypto::Unsealed::new_with_descriptor(<Self as cipherstash_dynamodb::traits::Identifiable>::type_name());

                #(#into_unsealed_impl)*

                unsealed
            }
        }
    };

    Ok(expanded)
}
