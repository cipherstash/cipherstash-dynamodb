use std::collections::HashMap;

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

    // Remaining fields
    #[serde(flatten)]
    pub(crate) attributes: HashMap<String, String>, // TODO: We will need to handle other types for plaintext values
}
