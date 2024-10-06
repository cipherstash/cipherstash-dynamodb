use cipherstash_client::{encryption::EncryptionError, zero_kms::EncryptedRecord};
use itertools::Itertools;
use crate::{crypto::{attrs::flattened_protected_attributes::FlattenedKey, SealError}, encrypted_table::TableAttributes, traits::TableAttribute};

// TODO: Move this elsewhere
/// Represents a set of encrypted records that have not yet been normalized into an output type.
pub(crate) struct FlattenedEncryptedAttributes(Vec<EncryptedRecord>);

impl FlattenedEncryptedAttributes {
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
