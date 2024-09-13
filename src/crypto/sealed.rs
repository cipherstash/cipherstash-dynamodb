use crate::{
    async_map_somes::async_map_somes,
    encrypted_table::{TableAttribute, TableEntry},
    traits::{ReadConversionError, WriteConversionError},
    Decryptable,
};
use aws_sdk_dynamodb::{primitives::Blob, types::AttributeValue};
use cipherstash_client::{
    credentials::{service_credentials::ServiceToken, Credentials},
    encryption::{Encryption, Plaintext},
};
use std::{borrow::Cow, collections::HashMap, ops::Deref};

use super::{SealError, Unsealed};

/// Wrapped to indicate that the value is encrypted
pub struct SealedTableEntry(pub(super) TableEntry);

pub struct UnsealSpec<'a> {
    pub protected_attributes: Cow<'a, [Cow<'a, str>]>,
    pub plaintext_attributes: Cow<'a, [Cow<'a, str>]>,
}

impl UnsealSpec<'static> {
    pub fn new_for_decryptable<D: Decryptable>() -> Self {
        Self {
            protected_attributes: D::protected_attributes(),
            plaintext_attributes: D::plaintext_attributes(),
        }
    }
}

impl SealedTableEntry {
    pub fn vec_from<O: TryInto<Self>>(
        items: impl IntoIterator<Item = O>,
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
    /// This should be used over [`Sealed::unseal`] when multiple values need to be unsealed.
    pub(crate) async fn unseal_all(
        items: impl AsRef<[SealedTableEntry]>,
        spec: UnsealSpec<'_>,
        cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
    ) -> Result<Vec<Unsealed>, SealError> {
        let items = items.as_ref();

        let UnsealSpec {
            protected_attributes,
            plaintext_attributes,
        } = spec;

        let mut plaintext_items: Vec<Vec<Option<&TableAttribute>>> =
            Vec::with_capacity(items.len());
        let mut decryptable_items = Vec::with_capacity(items.len() * protected_attributes.len());

        for item in items.iter() {
            if !protected_attributes.is_empty() {
                let ciphertexts = protected_attributes
                    .iter()
                    .map(|name| {
                        let attribute = item.inner().attributes.get(match name.deref() {
                            "pk" => "__pk",
                            "sk" => "__sk",
                            _ => name,
                        });

                        attribute
                            .map(|x| {
                                x.as_encrypted_record()
                                    .ok_or_else(|| SealError::InvalidCiphertext(name.to_string()))
                            })
                            .transpose()
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                // Create a list of all ciphertexts so that they can all be decrypted in one go.
                // The decrypted version of this list will be chunked up and zipped with the plaintext
                // fields once the decryption succeeds.
                decryptable_items.extend(ciphertexts);
            }

            let unprotected = plaintext_attributes
                .iter()
                .map(|name| {
                    let attr = match name.deref() {
                        "sk" => "__sk",
                        _ => name,
                    };

                    item.inner().attributes.get(attr)
                })
                .collect::<Vec<Option<&TableAttribute>>>();

            plaintext_items.push(unprotected);
        }

        let decrypted = async_map_somes(decryptable_items, |items| cipher.decrypt(items)).await?;

        let decrypted_iter: &mut dyn Iterator<Item = &[Option<Plaintext>]> =
            if protected_attributes.len() > 0 {
                &mut decrypted.chunks_exact(protected_attributes.len())
            } else {
                &mut std::iter::repeat_with::<&[Option<Plaintext>], _>(|| &[])
                    .take(plaintext_items.len())
            };

        let unsealed = decrypted_iter
            .zip(plaintext_items)
            .map(|(decrypted_plaintext, plaintext_items)| {
                let mut unsealed = Unsealed::new();

                for (name, plaintext) in protected_attributes.iter().zip(decrypted_plaintext) {
                    if let Some(plaintext) = plaintext {
                        unsealed.add_protected(name.to_string(), plaintext.clone());
                    }
                }

                for (name, plaintext) in
                    plaintext_attributes.iter().zip(plaintext_items.into_iter())
                {
                    if let Some(plaintext) = plaintext {
                        unsealed.add_unprotected(name.to_string(), plaintext.clone());
                    }
                }

                unsealed
            })
            .collect::<Vec<_>>();

        Ok(unsealed)
    }

    /// Unseal the current value and return it's plaintext representation
    ///
    /// If you need to unseal multiple values at once use [`Sealed::unseal_all`]
    pub(crate) async fn unseal(
        self,
        spec: UnsealSpec<'_>,
        cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
    ) -> Result<Unsealed, SealError> {
        let mut vec = Self::unseal_all([self], spec, cipher).await?;

        if vec.len() != 1 {
            let actual = vec.len();

            return Err(SealError::AssertionFailed(format!(
                "Expected unseal_all to return 1 result but got {actual}"
            )));
        }

        Ok(vec.remove(0))
    }
}

impl TryFrom<HashMap<String, AttributeValue>> for SealedTableEntry {
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

        Ok(SealedTableEntry(table_entry))
    }
}

impl TryFrom<SealedTableEntry> for HashMap<String, AttributeValue> {
    type Error = WriteConversionError;

    fn try_from(item: SealedTableEntry) -> Result<Self, Self::Error> {
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
