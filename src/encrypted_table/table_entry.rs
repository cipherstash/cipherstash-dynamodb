use crate::traits::{ReadConversionError, WriteConversionError, SearchableRecord};
use aws_sdk_dynamodb::types::AttributeValue;
use cipherstash_client::{
    credentials::{vitur_credentials::ViturToken, Credentials},
    encryption::{Encryption, Plaintext, compound_indexer::CompoundIndex, IndexTerm},
};
use std::{collections::HashMap, iter::once};

const MAX_TERMS_PER_INDEX: usize = 25;

// TODO: Override display and Debug
// TODO: Use Zeroize
/// Wrapper to indicate that a value is NOT encrypted
pub struct Unsealed<T> {
    inner: T,
    protected: HashMap<String, Plaintext>,
    unprotected: HashMap<String, TableAttribute>,
}

impl<T> Unsealed<T>
{
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            protected: Default::default(),
            unprotected: Default::default(),
        }
    }

    pub fn protected<P: TryInto<Plaintext>>(
        mut self,
        name: impl Into<String>,
        plaintext: P,
    ) -> Result<Self, WriteConversionError> {
        let name: String = name.into();

        self.protected.insert(
            name.to_string(),
            plaintext
                .try_into()
                .map_err(|_| WriteConversionError::ConversionFailed(name))?,
        );
        Ok(self)
    }

    pub fn plaintext<P: Into<TableAttribute>>(
        mut self,
        name: impl Into<String>,
        value: P,
    ) -> Result<Self, WriteConversionError> {
        self.unprotected.insert(name.into(), value.into());
        Ok(self)
    }

    pub(crate) async fn seal<C>(
        self,
        cipher: &Encryption<C>,
        term_length: usize
    // TODO: SealError
    ) -> (String, Vec<Sealed<TableEntry>>)
    where
        C: Credentials<Token = ViturToken>,
        T: SearchableRecord,
    {
        let mut table_entry = TableEntry::new_with_attributes(
            // TODO: Encrypt partition key? Make it optional?
            self.inner.partition_key(),
            T::type_name().to_string(),
            None,
            self.unprotected,
        );

        let i: Vec<(Plaintext, String)> = self
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
                if let Some(e) = enc {
                    table_entry.add_attribute(name, e.into());
                }
            });

        // Indexes
        (
            self.inner.partition_key(),
            once(Sealed(table_entry.clone()))
            .chain(
            T::protected_indexes().iter().flat_map(|index_name| {
            let (attr, index) = self.inner
                .attribute_for_index(*index_name)
                .and_then(|attr| T::index_by_name(*index_name)
                .and_then(|index| Some((attr, index))))
                .unwrap();

            let index_term = cipher.compound_index(
                &CompoundIndex::new(index),
                attr,
                Some(format!("{}#{}", T::type_name(), index_name)),
                term_length,
            ).unwrap(); // FIXME: Error

            let terms = match index_term {
                IndexTerm::Binary(x) => vec![x],
                IndexTerm::BinaryVec(x) => x,
                _ => todo!(),
            };

            terms.iter().enumerate().take(MAX_TERMS_PER_INDEX).map(|(i, term)| {
                Sealed(TableEntry::new_with_attributes(
                    self.inner.partition_key(),
                    format!("{}#{}#{}", T::type_name(), index_name, i), // TODO: HMAC the sort key, too (users#index_name#pk)
                    Some(hex::encode(term)),
                    table_entry.attributes.clone(),
                ))
            }).collect::<Vec<Sealed<TableEntry>>>()
        })).collect())

        
    }

    pub(crate) async fn unseal<C>(sealed: Sealed<TableEntry>, cipher: &Encryption<C>) -> Self
    where
        C: Credentials<Token = ViturToken>,
    {
        unimplemented!()
    }

    fn seal_iter<I>(iter: I) -> Vec<Sealed<TableEntry>>
    where
        I: IntoIterator<Item = Unsealed<T>>,
    {
        unimplemented!()
    }
}

/// Wrapped to indicate that the value is encrypted
pub struct Sealed<T>(T);

impl<T> Sealed<T> {
    pub fn vec_from<O: TryInto<Self>>(items: Vec<O>) -> Result<Vec<Self>, <O as TryInto<Self>>::Error> {
        items.into_iter().map(Self::from_inner).collect()
    }

    pub(super) fn from_inner<O: TryInto<Self>>(item: O) -> Result<Self, <O as TryInto<Self>>::Error> {
        item.try_into()
    }

    pub(super) fn into_inner(self) -> T {
        self.0
    }
    
    pub(super) fn inner(&self) -> &T {
        &self.0
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

    pub fn add_attribute(&mut self, k: impl Into<String>, v: TableAttribute) {
        self.attributes.insert(k.into(), v);
    }

    pub fn set_term(&mut self, term: String) {
        self.term = Some(term);
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
}

#[derive(Debug, Clone)]
pub enum TableAttribute {
    String(String),
    I32(i32),
    // TODO: More here
    Null,
}

impl From<String> for TableAttribute {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<i32> for TableAttribute {
    fn from(value: i32) -> Self {
        Self::I32(value)
    }
}

impl TryFrom<Sealed<TableEntry>> for HashMap<String, AttributeValue> {
    type Error = WriteConversionError;

    fn try_from(item: Sealed<TableEntry>) -> Result<Self, Self::Error> {
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

impl TryFrom<HashMap<String, AttributeValue>> for Sealed<TableEntry> {
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

            _ => unimplemented!(),
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
