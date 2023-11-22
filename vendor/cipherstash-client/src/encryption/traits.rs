use super::Plaintext;
use std::borrow::Cow;
use vitur_client::{EncryptPayload, Iv};

/// Trait that performs a conversion between
///
/// None is returned when the plaintext value is null and there is nothing to encrypt.
pub trait IntoEncryptionMaterial<'a> {
    fn into_encryption_material(self) -> Option<EncryptPayload<'a>>;
}

impl<D> IntoEncryptionMaterial<'static> for (&Plaintext, D)
where
    String: From<D>,
{
    fn into_encryption_material(self) -> Option<EncryptPayload<'static>> {
        let (plaintext, descriptor) = self;

        if plaintext.is_null() {
            return None;
        }

        let msg = plaintext.to_vec();

        Some(EncryptPayload {
            msg: msg.into(),
            descriptor: Cow::Owned(String::from(descriptor)),
            iv: None,
        })
    }
}

impl<D> IntoEncryptionMaterial<'static> for (&Plaintext, D, Option<Iv>)
where
    String: From<D>,
{
    fn into_encryption_material(self) -> Option<EncryptPayload<'static>> {
        let (plaintext, descriptor, iv) = self;

        if plaintext.is_null() {
            return None;
        }

        let msg = plaintext.to_vec();

        Some(EncryptPayload {
            msg: msg.into(),
            descriptor: Cow::Owned(String::from(descriptor)),
            iv,
        })
    }
}

impl<D> IntoEncryptionMaterial<'static> for (&Plaintext, D, Iv)
where
    String: From<D>,
{
    fn into_encryption_material(self) -> Option<EncryptPayload<'static>> {
        (self.0, self.1, Some(self.2)).into_encryption_material()
    }
}

impl<'a> IntoEncryptionMaterial<'a> for Option<EncryptPayload<'a>> {
    fn into_encryption_material(self) -> Option<EncryptPayload<'a>> {
        self
    }
}

impl<'a> IntoEncryptionMaterial<'a> for EncryptPayload<'a> {
    fn into_encryption_material(self) -> Option<EncryptPayload<'a>> {
        Some(self)
    }
}
