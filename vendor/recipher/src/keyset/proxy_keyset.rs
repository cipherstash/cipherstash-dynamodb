use serde::{Deserialize, Serialize};

// KeySet Generation
use super::encryption_keyset::EncryptionKeySet;
use crate::permutation::Permutation;

#[derive(Deserialize, Serialize, Clone)]
pub struct ProxyKeySet {
    pub(crate) p1: Permutation,
    pub(crate) p2_from: Permutation,
    pub(crate) p2_to: Permutation,
    pub(crate) p3: Permutation,
}

impl ProxyKeySet {
    pub fn generate(from: &EncryptionKeySet, to: &EncryptionKeySet) -> Self {
        Self {
            p1: to.p1.complement(&from.p1),
            p2_from: from.p2.clone(),
            p2_to: to.p2.clone(),
            p3: to.p3.complement(&from.p3),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_cbor::Error> {
        serde_cbor::to_vec(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> serde_cbor::Result<Self> {
        serde_cbor::from_slice(bytes)
    }
}
