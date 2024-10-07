use crate::{
    crypto::attrs::FlattenedEncryptedAttributes,
    encrypted_table::TableEntry,
    traits::{ReadConversionError, WriteConversionError},
    Decryptable, Identifiable,
};
use aws_sdk_dynamodb::{primitives::Blob, types::AttributeValue};
use cipherstash_client::{
    credentials::{service_credentials::ServiceToken, Credentials},
    encryption::Encryption,
};
use itertools::Itertools;
use std::{borrow::Cow, collections::HashMap};

use super::{attrs::NormalizedProtectedAttributes, SealError, Unsealed};

// FIXME: Move this to a separate file
/// Wrapped to indicate that the value is encrypted
pub struct SealedTableEntry(pub(super) TableEntry);

// FIXME: Remove this (only used for debugging)
#[derive(Debug)]
pub struct UnsealSpec<'a> {
    pub(crate) protected_attributes: Cow<'a, [Cow<'a, str>]>,

    /// The prefix used for sort keys.
    /// If None, the type name will be used.
    /// This *must* be the same as the value used when encrypting the data
    /// so that descriptors can be correctly matched.
    /// See [TableAttribute::as_encrypted_record]
    pub(crate) sort_key_prefix: String,
}

impl UnsealSpec<'static> {
    pub fn new_for_decryptable<D>() -> Self
    where
        D: Decryptable + Identifiable,
    {
        Self {
            protected_attributes: D::protected_attributes(),
            sort_key_prefix: D::sort_key_prefix()
                .as_deref()
                .map(ToOwned::to_owned)
                .unwrap_or(D::type_name().to_string()),
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

    pub(crate) fn into_inner(self) -> TableEntry {
        self.0
    }

    /// Unseal a list of [`Sealed`] values in an efficient manner that optimizes for bulk
    /// decryptions
    ///
    /// This should be used over [`Sealed::unseal`] when multiple values need to be unsealed.
    pub(crate) async fn unseal_all(
        items: Vec<SealedTableEntry>,
        spec: UnsealSpec<'_>,
        cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
    ) -> Result<Vec<Unsealed>, SealError> {
        let UnsealSpec {
            protected_attributes,
            sort_key_prefix,
        } = spec;

        let mut protected_items = {
            let capacity = items.len() * protected_attributes.len();
            FlattenedEncryptedAttributes::with_capacity(capacity)
        };
        let mut unprotected_items = Vec::with_capacity(items.len());

        for item in items.into_iter() {
            let (protected, unprotected) = item
                .into_inner()
                .attributes
                .partition(protected_attributes.as_ref());

            protected_items.try_extend(protected, sort_key_prefix.clone())?;
            unprotected_items.push(unprotected);
        }

        if protected_items.is_empty() {
            unprotected_items
                .into_iter()
                .map(|unprotected| {
                    // TODO: Create a new_from_unprotected method
                    Ok(Unsealed::new_from_parts(
                        NormalizedProtectedAttributes::new(),
                        unprotected,
                    ))
                })
                .collect()
        } else {
            let chunk_size = protected_items.len() / unprotected_items.len();

            protected_items
                .decrypt_all(cipher)
                .await?
                .into_iter()
                // TODO: Can we make decrypt_all return a Vec of FlattenedProtectedAttributes? (like the mirror of encrypt_all)
                .chunks(chunk_size)
                .into_iter()
                .map(|fpa| fpa.into_iter().collect::<NormalizedProtectedAttributes>())
                .zip_eq(unprotected_items.into_iter())
                .map(|(fpa, unprotected)| Ok(Unsealed::new_from_parts(fpa, unprotected)))
                .collect()
        }
    }

    /// Unseal the current value and return it's plaintext representation
    ///
    /// If you need to unseal multiple values at once use [`Sealed::unseal_all`]
    pub(crate) async fn unseal(
        self,
        spec: UnsealSpec<'_>,
        cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
    ) -> Result<Unsealed, SealError> {
        let mut vec = Self::unseal_all(vec![self], spec, cipher).await?;

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

        // This prevents loading special columns when retrieving records
        // pk/sk are handled specially or will be called __sk and __pk
        // We never want to read term during queries
        item.into_iter()
            .filter(|(k, _)| k != "pk" && k != "sk" && k != "term")
            .for_each(|(k, v)| {
                table_entry.add_attribute(k, v.into());
            });

        Ok(SealedTableEntry(table_entry))
    }
}

// TODO: Test this conversion
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
            map.insert(k.into_stored_name(), v.into());
        });

        Ok(map)
    }
}
