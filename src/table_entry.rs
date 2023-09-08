use std::collections::HashMap;

use cipherstash_client::encryption::Posting;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct TableEntry {
    // Everything hex strings for now
    //#[serde(with = "hex")]
    //pk: Vec<u8>,
    pub(crate) pk: String,
    //#[serde(with = "hex")]
    pub(crate) sk: String,
    //#[serde(with = "hex")]
    pub(crate) term: Option<String>, // TODO: Make term optional

    /// Optional field specified by postings
    //field: Option<String>,
    pub(crate) field: Option<String>,

    // Remaining fields
    #[serde(flatten)]
    pub(crate) attributes: HashMap<String, String>, // TODO: We will need to handle other types for plaintext values
}

impl TableEntry {
    pub(crate) fn new_posting(
        partition_key: impl Into<String>,
        field: impl Into<String>,
        posting: &Posting,
        attributes: HashMap<String, String>,
    ) -> Self {
        let field: String = field.into();
        Self {
            pk: partition_key.into(),
            // We need to prefix this with plaintext field name too so we can delete these later
            sk: format!("{}#{}", &field, hex::encode(&posting.field)),
            term: Some(hex::encode(&posting.term)),
            attributes,
            field: Some(field),
        }
    }
}
