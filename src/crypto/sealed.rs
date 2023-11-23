use crate::{
    encrypted_table::{TableAttribute, TableEntry},
    traits::{ReadConversionError, WriteConversionError},
    Decryptable,
};
use aws_sdk_dynamodb::types::AttributeValue;
use cipherstash_client::{
    credentials::{vitur_credentials::ViturToken, Credentials},
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

    pub(crate) async fn unseal<C, T>(self, cipher: &Encryption<C>) -> Result<T, SealError>
    where
        C: Credentials<Token = ViturToken>,
        T: Decryptable,
    {
        let ciphertexts = T::decryptable_attributes()
            .into_iter()
            .map(|name| {
                let attribute = if name == T::partition_key_field() {
                    self.inner().attributes.get(&format!("__{name}"))
                } else {
                    self.inner().attributes.get(name)
                };

                attribute
                    .ok_or_else(|| SealError::MissingAttribute(name.to_string()))?
                    .as_ciphertext()
                    .ok_or_else(|| SealError::InvalidCiphertext(name.to_string()))
            })
            .collect::<Result<Vec<&str>, SealError>>()?;

        let unprotected = T::plaintext_attributes()
            .into_iter()
            .map(|name| {
                self.inner()
                    .attributes
                    .get(name)
                    .ok_or(SealError::MissingAttribute(name.to_string()))
            })
            .collect::<Result<Vec<&TableAttribute>, SealError>>()?;

        let unsealed = T::decryptable_attributes()
            .into_iter()
            .zip(cipher.decrypt(ciphertexts).await?.into_iter())
            .fold(Unsealed::new(), |mut unsealed, (name, plaintext)| {
                unsealed.add_protected(name, plaintext);
                unsealed
            });

        T::plaintext_attributes()
            .into_iter()
            .zip(unprotected)
            .fold(unsealed, |mut unsealed, (name, table_attr)| {
                unsealed.add_unprotected(name, table_attr.clone());
                unsealed
            })
            .into_value()
    }
}

impl TryFrom<HashMap<String, AttributeValue>> for Sealed {
    type Error = ReadConversionError;

    fn try_from(item: HashMap<String, AttributeValue>) -> Result<Self, Self::Error> {
        // FIXME: pk and sk should be AttributeValue and term
        // let pk = item
        //     .get("pk")
        //     .ok_or(ReadConversionError::NoSuchAttribute("pk".to_string()))?
        //     .as_s()
        //     .unwrap()
        //     .to_string();

        let sk = item
            .get("sk")
            .ok_or(ReadConversionError::NoSuchAttribute("sk".to_string()))?
            .as_s()
            .unwrap()
            .to_string();

        let mut table_entry = TableEntry::new(sk);

        item.into_iter()
            .filter(|(k, _)| k != "sk" && k != "term")
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

        map.insert("sk".to_string(), AttributeValue::S(item.0.sk));

        if let Some(term) = item.0.term {
            map.insert("term".to_string(), AttributeValue::S(term));
        }

        item.0.attributes.into_iter().for_each(|(k, v)| {
            map.insert(k.to_string(), v.into());
        });

        Ok(map)
    }
}
