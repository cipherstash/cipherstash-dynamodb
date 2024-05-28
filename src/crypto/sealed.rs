use crate::{
    encrypted_table::{TableAttribute, TableEntry},
    traits::{ReadConversionError, WriteConversionError},
    Decryptable,
};
use aws_sdk_dynamodb::{primitives::Blob, types::AttributeValue};
use cipherstash_client::{
    credentials::{service_credentials::ServiceToken, Credentials},
    encryption::Encryption,
};
use std::collections::HashMap;

use super::{SealError, Unsealed};

/// Wrapped to indicate that the value is encrypted
pub struct Sealed(pub(super) TableEntry);

impl Sealed {
    pub fn vec_from<O: TryInto<Self>>(
        items: Vec<O>,
    ) -> Result<Vec<Self>, <O as TryInto<Self>>::Error> {
        items.into_iter().map(Self::from_inner).collect()
    }

    pub(super) fn from_inner<O: TryInto<Self>>(
        item: O,
    ) -> Result<Self, <O as TryInto<Self>>::Error> {
        item.try_into()
    }

    pub(crate) fn inner(&self) -> &TableEntry {
        &self.0
    }

    /// Unseal a list of [`Sealed`] values in an efficient manner that optimizes for bulk
    /// decryptions
    ///
    /// This should be used over [`Sealed::unseal_raw`] when multiple values need to be unsealed.
    pub(crate) async fn unseal_all_raw<C>(
        items: impl AsRef<[Sealed]>,
        plaintext_attributes: Vec<&'static str>,
        decryptable_attributes: Vec<&'static str>,
        cipher: &Encryption<C>,
    ) -> Result<Vec<Unsealed>, SealError>
    where
        C: Credentials<Token = ServiceToken>,
    {
        let items = items.as_ref();

        let mut plaintext_items: Vec<Vec<&TableAttribute>> = Vec::with_capacity(items.len());
        let mut decryptable_items = Vec::with_capacity(items.len() * decryptable_attributes.len());

        for item in items.iter() {
            let ciphertexts = decryptable_attributes
                .iter()
                .map(|name| {
                    let attribute = item.inner().attributes.get(match *name {
                        "pk" => "__pk",
                        "sk" => "__sk",
                        _ => name,
                    });

                    attribute
                        .ok_or_else(|| SealError::MissingAttribute(name.to_string()))?
                        .as_encrypted_record()
                        .ok_or_else(|| SealError::InvalidCiphertext(name.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;

            let unprotected = plaintext_attributes
                .iter()
                .map(|name| {
                    let attr = match *name {
                        "sk" => "__sk",
                        _ => name,
                    };

                    item.inner()
                        .attributes
                        .get(attr)
                        .ok_or(SealError::MissingAttribute(attr.to_string()))
                })
                .collect::<Result<Vec<&TableAttribute>, SealError>>()?;

            plaintext_items.push(unprotected);

            // Create a list of all ciphertexts so that they can all be decrypted in one go.
            // The decrypted version of this list will be chunked up and zipped with the plaintext
            // fields once the decryption succeeds.
            decryptable_items.extend(ciphertexts);
        }

        let decrypted = cipher.decrypt(decryptable_items).await?;

        let unsealed = decrypted
            .chunks_exact(decryptable_attributes.len())
            .zip(plaintext_items)
            .map(|(decrypted_plaintext, plaintext_items)| {
                let mut unsealed = Unsealed::new();

                for (name, plaintext) in decryptable_attributes.iter().zip(decrypted_plaintext) {
                    unsealed.add_protected(*name, plaintext.clone());
                }

                for (name, plaintext) in
                    plaintext_attributes.iter().zip(plaintext_items.into_iter())
                {
                    unsealed.add_unprotected(*name, plaintext.clone());
                }

                unsealed
            })
            .collect::<Vec<_>>();

        Ok(unsealed)
    }

    /// Unseal a list of [`Sealed`] values to T in an efficient manner that optimizes for bulk
    /// decryptions
    ///
    /// This should be used over [`Sealed::unseal`] when multiple values need to be unsealed.
    pub(crate) async fn unseal_all<T, C>(
        items: impl AsRef<[Sealed]>,
        cipher: &Encryption<C>,
    ) -> Result<Vec<T>, SealError>
    where
        C: Credentials<Token = ServiceToken>,
        T: Decryptable,
    {
        // let items = items.as_ref();
        let plaintext_attributes = T::plaintext_attributes();
        let decryptable_attributes = T::decryptable_attributes();

        Self::unseal_all_raw(items, plaintext_attributes, decryptable_attributes, cipher)
            .await?
            .into_iter()
            .map(Unsealed::into_value)
            .collect::<Result<Vec<_>, _>>()
    }

    /// Unseal the current value and return it's plaintext representation
    ///
    /// If you need to unseal multiple values at once use [`Sealed::unseal_all_raw`]
    pub(crate) async fn unseal_raw<C>(
        self,
        plaintext_attributes: Vec<&'static str>,
        decryptable_attributes: Vec<&'static str>,
        cipher: &Encryption<C>,
    ) -> Result<Unsealed, SealError>
    where
        C: Credentials<Token = ServiceToken>,
    {
        let mut vec =
            Self::unseal_all_raw([self], plaintext_attributes, decryptable_attributes, cipher)
                .await?;

        if vec.len() != 1 {
            let actual = vec.len();

            return Err(SealError::AssertionFailed(format!(
                "Expected unseal_all to return 1 result but got {actual}"
            )));
        }

        Ok(vec.remove(0))
    }

    /// Unseal the current value and return it's plaintext representation as T
    ///
    /// If you need to unseal multiple values at once use [`Sealed::unseal_all`]
    pub(crate) async fn unseal<C, T>(self, cipher: &Encryption<C>) -> Result<T, SealError>
    where
        C: Credentials<Token = ServiceToken>,
        T: Decryptable,
    {
        self.unseal_raw(
            T::plaintext_attributes(),
            T::decryptable_attributes(),
            cipher,
        )
        .await?
        .into_value()
    }
}

impl TryFrom<HashMap<String, AttributeValue>> for Sealed {
    type Error = ReadConversionError;

    fn try_from(item: HashMap<String, AttributeValue>) -> Result<Self, Self::Error> {
        // FIXME: pk and sk should be AttributeValue and term
        let pk = item
            .get("pk")
            .ok_or(ReadConversionError::NoSuchAttribute("pk".to_string()))?
            .as_s()
            .map_err(|_| ReadConversionError::InvalidFormat("pk".to_string()))?
            .to_string();

        let sk = item
            .get("sk")
            .ok_or(ReadConversionError::NoSuchAttribute("sk".to_string()))?
            .as_s()
            .map_err(|_| ReadConversionError::InvalidFormat("sk".to_string()))?
            .to_string();

        let mut table_entry = TableEntry::new(pk, sk);

        item.into_iter()
            .filter(|(k, _)| k != "pk" && k != "sk" && k != "term")
            .for_each(|(k, v)| {
                table_entry.add_attribute(&k, v.into());
            });

        Ok(Sealed(table_entry))
    }
}

impl TryFrom<Sealed> for HashMap<String, AttributeValue> {
    type Error = WriteConversionError;

    fn try_from(item: Sealed) -> Result<Self, Self::Error> {
        let mut map = HashMap::new();

        map.insert("pk".to_string(), AttributeValue::S(item.0.pk));
        map.insert("sk".to_string(), AttributeValue::S(item.0.sk));

        if let Some(term) = item.0.term {
            map.insert("term".to_string(), AttributeValue::B(Blob::new(term)));
        }

        item.0.attributes.into_iter().for_each(|(k, v)| {
            map.insert(
                match k.as_str() {
                    "sk" => "__sk".to_string(),
                    _ => k,
                },
                v.into(),
            );
        });

        Ok(map)
    }
}
