use crate::traits::ReadConversionError;
use aws_sdk_dynamodb::{primitives::Blob, types::AttributeValue};
use std::collections::HashMap;

// FIXME: Clean this up
//#[skip_serializing_none]
#[derive(Debug, Clone)]
pub struct TableEntry {
    //#[serde(with = "hex")]
    pub(crate) sk: String,

    //#[serde(with = "hex")]
    pub(crate) term: Option<String>,

    // Remaining fields
    //#[serde(flatten)]
    pub(crate) attributes: HashMap<String, TableAttribute>,
}

impl TableEntry {
    pub fn new(sk: String) -> Self {
        Self {
            sk,
            term: None,
            attributes: HashMap::new(),
        }
    }

    pub fn new_with_attributes(
        sk: String,
        term: Option<String>,
        attributes: HashMap<String, TableAttribute>,
    ) -> Self {
        Self {
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
    Number(String),
    Bool(bool),
    Bytes(Vec<u8>),

    StringVec(Vec<String>),
    ByteVec(Vec<Vec<u8>>),
    NumberVec(Vec<String>),

    Map(HashMap<String, TableAttribute>),
    List(Vec<TableAttribute>),

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

macro_rules! impl_option_conversion {
    ($($type:ty),*) => {
        $(
            impl From<Option<$type>> for TableAttribute {
                fn from(value: Option<$type>) -> Self {
                    if let Some(value) = value {
                        value.into()
                    } else {
                        TableAttribute::Null
                    }
                }
            }

            impl TryFrom<TableAttribute> for Option<$type> {
                type Error = ReadConversionError;

                fn try_from(value: TableAttribute) -> Result<Self, Self::Error> {
                    if let TableAttribute::Null = value {
                        return Ok(None);
                    }

                    value.try_into().map(Some)
                }
            }
        )*
    };
}

macro_rules! impl_number_conversions {
    ($($type:ty),*) => {
        $(
            impl From<$type> for TableAttribute {
                fn from(v: $type) -> Self {
                    Self::Number(v.to_string())
                }
            }

            impl From<Vec<$type>> for TableAttribute {
                fn from(v: Vec<$type>) -> Self {
                    Self::NumberVec(v.into_iter().map(|x| x.to_string()).collect())
                }
            }

            impl From<&$type> for TableAttribute {
                fn from(v: &$type) -> Self {
                    Self::Number(v.to_string())
                }
            }

            impl TryFrom<TableAttribute> for Vec<$type> {
                type Error = ReadConversionError;

                fn try_from(value: TableAttribute) -> Result<Self, Self::Error> {
                    if let TableAttribute::NumberVec(x) = value {
                        x.into_iter().map(|x| x.parse().map_err(|_| ReadConversionError::ConversionFailed(stringify!($type).to_string()))).collect::<Result<_, _>>()
                    } else {
                        Err(ReadConversionError::ConversionFailed(stringify!($type).to_string()))
                    }
                }
            }

            impl TryFrom<TableAttribute> for $type {
                type Error = ReadConversionError;

                fn try_from(value: TableAttribute) -> Result<Self, Self::Error> {
                    if let TableAttribute::Number(x) = value {
                        x.parse().map_err(|_| ReadConversionError::ConversionFailed(stringify!($type).to_string()))
                    } else {
                        Err(ReadConversionError::ConversionFailed(stringify!($type).to_string()))
                    }
                }
            }

            impl_option_conversion! {
                $type,
                Vec<$type>
            }
        )*
    }
}

macro_rules! impl_simple_conversions {
    ($($variant:ident => $type:ty),*) => {
            $(
                impl From<$type> for TableAttribute {
                    fn from(v: $type) -> Self {
                        TableAttribute::$variant(v)
                    }
                }

                impl From<&$type> for TableAttribute {
                    fn from(v: &$type) -> Self {
                        TableAttribute::$variant(v.to_owned())
                    }
                }

                impl TryFrom<TableAttribute> for $type {
                    type Error = ReadConversionError;

                    fn try_from(v: TableAttribute) -> Result<Self, Self::Error> {
                        if let TableAttribute::$variant(x) = v {
                            Ok(x.into())
                        } else {
                            Err(ReadConversionError::ConversionFailed(stringify!($type).to_string()))
                        }
                    }
                }

                impl_option_conversion! {
                    $type
                }
            )*
    }
}

impl_number_conversions! {
    i16,
    i32,
    i64,
    u16,
    u32,
    u64,
    usize,
    f32,
    f64
}

impl_simple_conversions! {
    String => String,
    Bytes => Vec<u8>,
    StringVec => Vec<String>,
    ByteVec => Vec<Vec<u8>>
}

impl From<TableAttribute> for AttributeValue {
    fn from(attribute: TableAttribute) -> Self {
        match attribute {
            TableAttribute::String(s) => AttributeValue::S(s),
            TableAttribute::StringVec(s) => AttributeValue::Ss(s),

            TableAttribute::Number(i) => AttributeValue::N(i.to_string()),
            TableAttribute::NumberVec(x) => AttributeValue::Ns(x),

            TableAttribute::Bytes(x) => AttributeValue::B(Blob::new(x)),
            TableAttribute::ByteVec(x) => {
                AttributeValue::Bs(x.into_iter().map(|x| Blob::new(x)).collect())
            }

            TableAttribute::Bool(x) => AttributeValue::Bool(x),
            TableAttribute::List(x) => AttributeValue::L(x.into_iter().map(|x| x.into()).collect()),
            TableAttribute::Map(x) => {
                AttributeValue::M(x.into_iter().map(|(k, v)| (k, v.into())).collect())
            }

            TableAttribute::Null => AttributeValue::Null(true),
        }
    }
}

impl From<AttributeValue> for TableAttribute {
    fn from(attribute: AttributeValue) -> Self {
        match attribute {
            AttributeValue::S(s) => TableAttribute::String(s),
            AttributeValue::N(n) => TableAttribute::Number(n),
            AttributeValue::Bool(n) => TableAttribute::Bool(n),
            AttributeValue::B(n) => TableAttribute::Bytes(n.into_inner()),
            AttributeValue::L(l) => {
                TableAttribute::List(l.into_iter().map(TableAttribute::from).collect())
            }
            AttributeValue::M(l) => TableAttribute::Map(
                l.into_iter()
                    .map(|(k, v)| (k, TableAttribute::from(v)))
                    .collect(),
            ),
            AttributeValue::Bs(x) => {
                TableAttribute::ByteVec(x.into_iter().map(|x| x.into_inner()).collect())
            }
            AttributeValue::Ss(x) => TableAttribute::StringVec(x),
            AttributeValue::Ns(x) => TableAttribute::NumberVec(x),
            AttributeValue::Null(_) => TableAttribute::Null,

            x => panic!("Unsupported Dynamo attribute value: {x:?}"),
        }
    }
}
