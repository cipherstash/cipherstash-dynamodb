use serde::{Deserialize, Serialize};

use crate::credentials::TokenExpiry;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViturToken {
    pub(crate) access_token: String,
    pub(crate) expiry: u64,
}

impl ViturToken {
    pub fn access_token(&self) -> String {
        self.access_token.to_string()
    }
}

impl TokenExpiry<'_> for ViturToken {
    fn expires_at_secs(&self) -> u64 {
        self.expiry
    }
}
