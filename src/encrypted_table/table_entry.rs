use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;
use cipherstash_client::encryption::Plaintext;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

//#[skip_serializing_none]
#[derive(Debug)]
pub struct TableEntry {
    // Everything hex strings for now
    //#[serde(with = "hex")]
    //pk: Vec<u8>,
    pub(crate) pk: String,
    //#[serde(with = "hex")]
    pub(crate) sk: String,

    //#[serde(with = "hex")]
    pub(crate) term: Option<String>, // TODO: Make term optional

    // Remaining fields
    //#[serde(flatten)]
    pub(crate) attributes: HashMap<String, AttributeValue>,
}

impl TableEntry {
    pub fn new(pk: String, sk: String, term: Option<String>, attributes: HashMap<String, AttributeValue>) -> Self {
        Self {
            pk,
            sk,
            term,
            attributes,
        }
    }

    pub fn to_item(self) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        item.insert("pk".to_string(), AttributeValue::S(self.pk));
        item.insert("sk".to_string(), AttributeValue::S(self.sk));
        if let Some(term) = self.term {
            item.insert("term".to_string(), AttributeValue::S(term));
        }
        for (k, v) in self.attributes {
            item.insert(k, v);
        }
        item
    }

    // FIXME: Use a proper error type
    pub fn from_item(item: HashMap<String, AttributeValue>) -> Self {
        let pk = item.get("pk").unwrap().as_s().unwrap().to_string();
        let sk = item.get("sk").unwrap().as_s().unwrap().to_string();
        let term = item.get("term").map(|v| v.as_s().unwrap().to_string());

        let attributes = item
            .into_iter()
            .filter(|(k, _)| k != "pk" && k != "sk" && k != "term")
            .collect();

        Self {
            pk,
            sk,
            term,
            attributes,
        }
    }
}

pub enum TableAttribute {
    String(String),
    I32(i32),

    Null,
}

impl From<TableAttribute> for AttributeValue {
    fn from(attribute: TableAttribute) -> Self {
        match attribute {
            TableAttribute::String(s) => AttributeValue::S(s),
            TableAttribute::I32(i) => AttributeValue::N(i.to_string()),
            TableAttribute::Null => AttributeValue::Null(true),
            _ => unimplemented!()
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
