use cipherstash_client::{credentials::{service_credentials::ServiceToken, Credentials}, encryption::{Encryption, EncryptionError}, zero_kms::EncryptedRecord};
use itertools::Itertools;
use crate::{crypto::{attrs::flattened_protected_attributes::FlattenedKey, SealError}, encrypted_table::{TableAttributes, TableEntry}, traits::TableAttribute};

use super::FlattenedProtectedAttributes;

// TODO: Move this elsewhere
/// Represents a set of encrypted records that have not yet been normalized into an output type.
// TODO: Remove the Debug derive
#[derive(Debug)]
pub(crate) struct FlattenedEncryptedAttributes(Vec<EncryptedRecord>);

impl FlattenedEncryptedAttributes {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    // TODO: REmove this
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    // TODO: Test this
    /// Decrypt self, returning a [FlattenedProtectedAttributes].
    pub(crate) async fn decrypt_all(
        self,
        cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
    ) -> Result<FlattenedProtectedAttributes, SealError> {
        let descriptors = self.0.iter().map(|record| record.descriptor.clone()).collect_vec();

        cipher
            .decrypt(self.0.into_iter())
            .await
            .map(|records| {
                records
                    .into_iter()
                    .zip(descriptors.into_iter())
                    .collect()
            })
            .map_err(SealError::from)
    }

    /// Denormalize the encrypted records into a TableAttributes.
    /// The descriptor is parsed into a [FlattenedKey] which is used to determine the key and subkey.
    /// If a subkey is present, the attribute is inserted to a map with the key and subkey.
    pub(crate) fn denormalize(self) -> Result<TableAttributes, SealError> {
        self.0
            .into_iter()
            .map(|record| {
                record
                    .to_vec()
                    .map(|data| (FlattenedKey::parse(&record.descriptor), data))
                    .map_err(EncryptionError::from)
            })
            .fold_ok(Ok(TableAttributes::new()), |acc, (flattened_key, bytes)| {
                let (key, subkey) = flattened_key.into_key_parts();
                if let Some(subkey) = subkey {
                    acc
                    .and_then(|mut acc| acc
                        .try_insert_map(key, subkey, bytes)
                        .map(|_| acc))
                } else {
                    acc.map(|mut acc| {
                        acc.insert(key, bytes);
                        acc
                    })
                }
            })?
    }

    // TODO: Test this
    /// Normalize the TableAttributes into a set of encrypted records.
    pub(crate) fn try_extend(&mut self, attributes: TableAttributes) {
        for (key, value) in attributes.into_iter() {
            match value {
                TableAttribute::Map(map) => {
                    for (subkey, value) in map.into_iter() {
                        let descriptor = FlattenedKey::from(key.as_str()).with_subkey(subkey);
                        // TODO: This is where we check that attr names match the descriptor to prevent confused deputy attacks
                        // TODO: The prefix is ideally included here while doing this check
                        self.0.push(value.as_encrypted_record().unwrap()); // TODO: throw an error
                    }
                }
                TableAttribute::Bytes(_) => {
                    let descriptor = FlattenedKey::from(key.as_str());
                    // TODO: Confused deputy attack check
                    self.0.push(value.as_encrypted_record().unwrap()); // TODO: throw an error
                }
                _ => todo!(), // TODO: throw an error
            }
        }
    }
}

impl From<Vec<EncryptedRecord>> for FlattenedEncryptedAttributes {
    fn from(records: Vec<EncryptedRecord>) -> Self {
        Self(records)
    }
}

impl FromIterator<EncryptedRecord> for FlattenedEncryptedAttributes {
    fn from_iter<T: IntoIterator<Item = EncryptedRecord>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}