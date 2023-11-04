use crate::{
    traits::{ReadConversionError},
};
use aws_sdk_dynamodb::types::AttributeValue;
use cipherstash_client::encryption::Plaintext;
use paste::paste;
use std::collections::HashMap;

// FIXME: Clean this up
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
    pub(crate) fn as_ciphertext(&self) -> Option<&str> {
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

// FIXME: This probably should not be a thing...right?
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
