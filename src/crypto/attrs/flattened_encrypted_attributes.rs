use crate::{
    crypto::{attrs::flattened_protected_attributes::FlattenedAttrName, SealError},
    encrypted_table::TableAttributes,
    traits::TableAttribute,
};
use cipherstash_client::{
    credentials::{service_credentials::ServiceToken, Credentials},
    encryption::{Encryption, EncryptionError},
    zero_kms::EncryptedRecord,
};
use itertools::Itertools;

use super::FlattenedProtectedAttributes;

/// Represents a set of encrypted records that have not yet been normalized into an output type.
pub(crate) struct FlattenedEncryptedAttributes {
    attrs: Vec<EncryptedRecord>,
}

impl FlattenedEncryptedAttributes {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            attrs: Vec::with_capacity(capacity),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.attrs.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.attrs.len()
    }

    // TODO: Test this
    /// Decrypt self, returning a [FlattenedProtectedAttributes].
    pub(crate) async fn decrypt_all(
        self,
        cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
    ) -> Result<FlattenedProtectedAttributes, SealError> {
        let descriptors = self
            .attrs
            .iter()
            .map(|record| record.descriptor.clone())
            .collect_vec();

        cipher
            .decrypt(self.attrs.into_iter())
            .await
            .map(|records| records.into_iter().zip(descriptors.into_iter()).collect())
            .map_err(SealError::from)
    }

    /// Denormalize the encrypted records into a TableAttributes.
    /// The descriptor is parsed into a [FlattenedKey] which is used to determine the key and subkey.
    /// If a subkey is present, the attribute is inserted to a map with the key and subkey.
    pub(crate) fn denormalize(self) -> Result<TableAttributes, SealError> {
        self.attrs
            .into_iter()
            .map(|record| {
                record
                    .to_vec()
                    .map(|data| (FlattenedAttrName::parse(&record.descriptor), data))
                    .map_err(EncryptionError::from)
            })
            .fold_ok(
                Ok(TableAttributes::new()),
                |acc, (flattened_attr_name, bytes)| {
                    let (name, subkey) = flattened_attr_name.into_parts();
                    if let Some(subkey) = subkey {
                        acc.and_then(|mut acc| acc.try_insert_map(name, subkey, bytes).map(|_| acc))
                    } else {
                        acc.map(|mut acc| {
                            acc.insert(name, bytes);
                            acc
                        })
                    }
                },
            )?
    }

    // TODO: Test this
    /// Normalize the TableAttributes into a set of encrypted records.
    /// An error will be returned if the TableAttributes contain an unsupported attribute type
    /// (only `Bytes` and `Map` are currently supported).
    ///
    /// Bytes data is converted to an [EncryptedRecord] using [TableAttribute::as_encrypted_record]
    /// which validates that the descriptor matches the key and subkey.
    ///
    /// This method is used during decrypt and load operations.
    pub(crate) fn try_extend(
        &mut self,
        attributes: TableAttributes,
        prefix: String,
    ) -> Result<(), SealError> {
        for (name, value) in attributes.into_iter() {
            match value {
                TableAttribute::Map(map) => {
                    for (subkey, value) in map.into_iter() {
                        let attr_key = FlattenedAttrName::new(Some(prefix.clone()), name.clone())
                            .with_subkey(subkey);
                        // Load the bytes and check for a confused deputy attack
                        let record = value.as_encrypted_record(&attr_key.descriptor())?;
                        self.attrs.push(record);
                    }
                }
                TableAttribute::Bytes(_) => {
                    let attr_key = FlattenedAttrName::new(Some(prefix.clone()), name);
                    // Load the bytes and check for a confused deputy attack
                    let record = value.as_encrypted_record(&attr_key.descriptor())?;
                    self.attrs.push(record);
                }
                _ => {
                    Err(SealError::AssertionFailed(
                        "Unsupported attribute type".to_string(),
                    ))?;
                }
            }
        }

        Ok(())
    }
}

impl From<Vec<EncryptedRecord>> for FlattenedEncryptedAttributes {
    fn from(attrs: Vec<EncryptedRecord>) -> Self {
        Self { attrs }
    }
}

impl FromIterator<EncryptedRecord> for FlattenedEncryptedAttributes {
    fn from_iter<T: IntoIterator<Item = EncryptedRecord>>(iter: T) -> Self {
        Self {
            attrs: iter.into_iter().collect(),
        }
    }
}
