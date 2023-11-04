use crate::{
    crypto::encrypt_partition_key,
    traits::{DecryptedRecord, ReadConversionError, SearchableRecord, WriteConversionError},
};
use aws_sdk_dynamodb::types::AttributeValue;
use cipherstash_client::{
    credentials::{vitur_credentials::ViturToken, Credentials},
    encryption::{
        compound_indexer::CompoundIndex, Encryption, EncryptionError, IndexTerm, Plaintext,
        TypeParseError,
    },
};
use paste::paste;
use std::{collections::HashMap, iter::once};
use thiserror::Error;

const MAX_TERMS_PER_INDEX: usize = 25;

// TODO: Override display and Debug
// TODO: Use Zeroize
/// Builder pattern for sealing a record of type, `T`.
pub struct Sealer<T> {
    inner: T,
    unsealed: Unsealed,
}

impl<T> Sealer<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            unsealed: Unsealed::new(),
        }
    }

    pub fn add_protected<F>(mut self, name: impl Into<String>, f: F) -> Result<Self, SealError>
    where
        F: FnOnce(&T) -> Plaintext,
    {
        let name: String = name.into();

        self.unsealed.add_protected(name, f(&self.inner));
        Ok(self)
    }

    pub fn add_plaintext<F>(mut self, name: impl Into<String>, f: F) -> Result<Self, SealError>
    where
        F: FnOnce(&T) -> TableAttribute,
    {
        let name: String = name.into();
        self.unsealed.add_unprotected(name, f(&self.inner));
        Ok(self)
    }

    pub(crate) async fn seal<C>(
        self,
        cipher: &Encryption<C>,
        term_length: usize, // TODO: SealError
    ) -> (String, Vec<Sealed>)
    where
        C: Credentials<Token = ViturToken>,
        T: SearchableRecord,
    {
        let pk = encrypt_partition_key(&self.inner.partition_key(), cipher).unwrap(); // FIXME

        let mut table_entry = TableEntry::new_with_attributes(
            pk.clone(),
            T::type_name().to_string(),
            None,
            self.unsealed.unprotected(),
        );

        // FIXME: This can all be simplified into one iterator
        // Make `get_protected` return the descriptor as well (keep them in the unsealed hash so we can pass references)
        // Protected plaintexts in order defined by protected_attributes
        let protected = T::protected_attributes()
            .into_iter()
            .map(|name| {
                self.unsealed
                    .get_protected(name)
                    .map(|plaintext| (name, plaintext.clone())) // TODO: Don't clone Plaintext
            })
            .collect::<Result<Vec<(&str, Plaintext)>, _>>()
            .unwrap(); // FIXME

        let i: Vec<(Plaintext, String)> = self
            .unsealed
            .protected
            .into_iter()
            .map(|(name, plaintext)| {
                // (plaintext, descriptor)
                (plaintext, format!("{}#{}", T::type_name(), name))
            })
            .collect();

        cipher
            .encrypt(
                i.iter()
                    .map(|(plaintext, descriptor)| (plaintext, descriptor.as_str())),
            )
            .await
            .unwrap() // FIXME
            .into_iter()
            .zip(T::protected_attributes().into_iter())
            .for_each(|(enc, name)| {
                dbg!((&enc, &name));
                if let Some(e) = enc {
                    table_entry.add_attribute(name, e.into());
                }
            });

        let table_entries = T::protected_indexes()
            .iter()
            .flat_map(|index_name| {
                let (attr, index) = self
                    .inner
                    .attribute_for_index(index_name)
                    .and_then(|attr| T::index_by_name(index_name).map(|index| (attr, index)))
                    .unwrap();

                let index_term = cipher
                    .compound_index(
                        &CompoundIndex::new(index),
                        attr,
                        Some(format!("{}#{}", T::type_name(), index_name)),
                        term_length,
                    )
                    .unwrap(); // FIXME: Error

                let terms = match index_term {
                    IndexTerm::Binary(x) => vec![x],
                    IndexTerm::BinaryVec(x) => x,
                    _ => todo!(),
                };

                terms
                    .iter()
                    .enumerate()
                    .take(MAX_TERMS_PER_INDEX)
                    .map(|(i, term)| {
                        Sealed(
                            table_entry
                                .clone()
                                .set_term(hex::encode(term))
                                // TODO: HMAC the sort key, too (users#index_name#pk)
                                .set_sk(format!("{}#{}#{}", T::type_name(), index_name, i)),
                        )
                    })
                    .collect::<Vec<Sealed>>()
            })
            .chain(once(Sealed(table_entry.clone())))
            .collect();

        (pk, table_entries)
    }

    #[allow(dead_code)]
    fn seal_iter<I>(_iter: I) -> Vec<Sealed>
    where
        I: IntoIterator<Item = Self>,
    {
        unimplemented!()
    }
}

// TODO: Zeroize, Debug, Display overrides (from SafeVec?)
/// Wrapper to indicate that a value is NOT encrypted
pub struct Unsealed {
    /// Protected plaintexts with their descriptors
    protected: HashMap<String, (Plaintext, String)>,
    unprotected: HashMap<String, TableAttribute>,
}

impl Unsealed {
    // TODO: Pass the "type_name" here as a decriptor prefix
    fn new() -> Self {
        Self {
            protected: Default::default(),
            unprotected: Default::default(),
        }
    }

    pub fn from_protected(&self, name: &str) -> Result<Plaintext, SealError> {
        Ok(self
            .protected
            .get(name)
            .ok_or(SealError::MissingAttribute(name.to_string()))?
            .clone())
    }

    pub fn from_plaintext(&self, name: &str) -> Result<TableAttribute, SealError> {
        Ok(self
            .unprotected
            .get(name)
            .ok_or(SealError::MissingAttribute(name.to_string()))?
            .clone())
    }

    fn add_protected(&mut self, name: impl Into<String>, plaintext: Plaintext) {
        self.protected.insert(name.into(), (plaintext, format!("{}#{}", T::type_name(), name)));
    }

    fn add_unprotected(&mut self, name: impl Into<String>, attribute: TableAttribute) {
        self.unprotected.insert(name.into(), attribute);
    }

    pub(crate) fn get_protected(&self, name: &str) -> Result<&Plaintext, SealError> {
        self.protected.get(name).ok_or(SealError::MissingAttribute(name.to_string()))
    }

    pub(crate) fn unprotected(&self) -> HashMap<String, TableAttribute> {
        self.unprotected.clone()
    }

    fn into_value<T>(self) -> Result<T, SealError>
    where
        T: DecryptedRecord,
    {
        T::from_unsealed(self)
    }
}

#[derive(Debug, Error)]
pub enum SealError {
    #[error("Failed to encrypt partition key")]
    CryptoError(#[from] EncryptionError),
    #[error("Failed to convert attribute: {0} from internal representation")]
    ReadConversionError(#[from] ReadConversionError),
    #[error("Failed to convert attribute: {0} to internal representation")]
    WriteConversionError(#[from] WriteConversionError),
    // TODO: Does TypeParseError correctly redact the plaintext value?
    #[error("Failed to parse type for encryption: {0}")]
    TypeParseError(#[from] TypeParseError),
    #[error("Missing attribute: {0}")]
    MissingAttribute(String),
    #[error("Invalid ciphertext value: {0}")]
    InvalidCiphertext(String),
}

/// Wrapped to indicate that the value is encrypted
pub struct Sealed(TableEntry);

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

    pub(super) fn inner(&self) -> &TableEntry {
        &self.0
    }

    pub(crate) async fn unseal<C, T>(self, cipher: &Encryption<C>) -> Result<T, SealError>
    where
        C: Credentials<Token = ViturToken>,
        T: DecryptedRecord,
    {
        let ciphertexts = T::decryptable_attributes()
            .into_iter()
            .map(|name| {
                self.inner()
                    .attributes
                    .get(name)
                    .ok_or(SealError::MissingAttribute(name.to_string()))?
                    .as_ciphertext()
                    .ok_or(SealError::InvalidCiphertext(name.to_string()))
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

//#[skip_serializing_none]
#[derive(Debug, Clone)]
pub struct TableEntry {
    // Everything hex strings for now
    //#[serde(with = "hex")]
    //pk: Vec<u8>,
    pub(crate) pk: String,
    //#[serde(with = "hex")]
    pub(crate) sk: String,

    //#[serde(with = "hex")]
    pub(crate) term: Option<String>,

    // Remaining fields
    //#[serde(flatten)]
    pub(crate) attributes: HashMap<String, TableAttribute>,
}

impl TableEntry {
    pub fn new(pk: String, sk: String) -> Self {
        Self {
            pk,
            sk,
            term: None,
            attributes: HashMap::new(),
        }
    }

    pub fn new_with_attributes(
        pk: String,
        sk: String,
        term: Option<String>,
        attributes: HashMap<String, TableAttribute>,
    ) -> Self {
        Self {
            pk,
            sk,
            term,
            attributes,
        }
    }

    pub fn add_attribute(&mut self, k: impl Into<String>, v: TableAttribute) {
        self.attributes.insert(k.into(), v);
    }

    pub(crate) fn set_term(mut self, term: impl Into<String>) -> Self {
        self.term = Some(term.into());
        self
    }

    pub(crate) fn set_sk(mut self, sk: impl Into<String>) -> Self {
        self.sk = sk.into();
        self
    }
}

#[derive(Debug, Clone)]
pub enum TableAttribute {
    String(String),
    I32(i32),
    // TODO: More here
    Null,
}

impl TableAttribute {
    fn as_ciphertext(&self) -> Option<&str> {
        if let TableAttribute::String(s) = self {
            Some(s)
        } else {
            None
        }
    }
}

macro_rules! impl_table_attribute_conversion {
    ($type:ident) => {
        paste! {
            impl From<$type> for TableAttribute {
                fn from(value: $type) -> Self {
                    Self::[<$type:camel>](value)
                }
            }

            impl From<&$type> for TableAttribute {
                fn from(value: &$type) -> Self {
                    Self::[<$type:camel>](value.clone())
                }
            }

            impl TryFrom<TableAttribute> for $type {
                type Error = ReadConversionError;

                fn try_from(value: TableAttribute) -> Result<Self, Self::Error> {
                    if let TableAttribute::[<$type:camel>](x) = value {
                        Ok(x)
                    } else {
                        Err(ReadConversionError::ConversionFailed(stringify!($type).to_string()))
                    }
                }
            }
        }
    };
}

impl_table_attribute_conversion!(String);
impl_table_attribute_conversion!(i32);

impl TryFrom<Sealed> for HashMap<String, AttributeValue> {
    type Error = WriteConversionError;

    fn try_from(item: Sealed) -> Result<Self, Self::Error> {
        let mut map = HashMap::new();

        map.insert("pk".to_string(), AttributeValue::S(item.0.pk));
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

impl TryFrom<HashMap<String, AttributeValue>> for Sealed {
    type Error = ReadConversionError;

    fn try_from(item: HashMap<String, AttributeValue>) -> Result<Self, Self::Error> {
        // FIXME: pk and sk should be AttributeValue and term
        let pk = item
            .get("pk")
            .ok_or(ReadConversionError::NoSuchAttribute("pk".to_string()))?
            .as_s()
            .unwrap()
            .to_string();

        let sk = item
            .get("sk")
            .ok_or(ReadConversionError::NoSuchAttribute("sk".to_string()))?
            .as_s()
            .unwrap()
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

impl From<TableAttribute> for AttributeValue {
    fn from(attribute: TableAttribute) -> Self {
        match attribute {
            TableAttribute::String(s) => AttributeValue::S(s),
            TableAttribute::I32(i) => AttributeValue::N(i.to_string()),
            TableAttribute::Null => AttributeValue::Null(true),
        }
    }
}

impl From<AttributeValue> for TableAttribute {
    fn from(attribute: AttributeValue) -> Self {
        match attribute {
            AttributeValue::S(s) => TableAttribute::String(s),
            AttributeValue::N(n) => TableAttribute::I32(n.parse().unwrap()),

            _ => unimplemented!(),
        }
    }
}

impl TryFrom<Plaintext> for TableAttribute {
    type Error = String;

    fn try_from(plaintext: Plaintext) -> Result<Self, Self::Error> {
        match plaintext {
            Plaintext::Utf8Str(Some(s)) => Ok(TableAttribute::String(s)),
            Plaintext::Int(Some(i)) => Ok(TableAttribute::I32(i)),
            // Null variants
            Plaintext::Utf8Str(None) => Ok(TableAttribute::Null),
            _ => Err("Unsupported plaintext type".to_string()),
        }
    }
}
