pub use recipher::{
    cipher::ProxyCipher,
    key::{GenRandom, Iv, Key},
    keyset::ProxyKeySet as KeySet,
};

use sha2::{Digest, Sha256};
use std::ops::Deref;
use vitur_protocol::ViturKeyMaterial;

#[derive(Clone)]
pub struct ClientKey {
    pub key_id: String,
    pub keyset: KeySet,
}

impl ClientKey {
    pub fn from_bytes(
        key_id: impl Into<String>,
        bytes: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            key_id: key_id.into(),
            keyset: KeySet::from_bytes(bytes)?,
        })
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct DataKey {
    pub iv: Iv,
    pub key: Key,
}

impl DataKey {
    /// Create a [`DataKey`] for a specific [`ClientKey`] given a specific initialisation vector
    /// (IV) and key material obtained from Vitur.
    pub fn from_key_material(key: &ClientKey, iv: Iv, key_material: &ViturKeyMaterial) -> Self {
        let cipher = ProxyCipher::new(&key.keyset);
        let rect = cipher.reencrypt::<16>(&iv, key_material);

        let mut hasher = Sha256::new();
        hasher.update(&rect);

        DataKey {
            iv,
            key: hasher.finalize().into(),
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct DataKeyWithTag {
    pub key: DataKey,
    pub tag: Vec<u8>,
}

impl DataKeyWithTag {
    /// Create a [`DataKey`] for a specific [`ClientKey`] given a specific IV, key material and tag
    /// obtained from Vitur.
    pub fn from_key_material(
        key: &ClientKey,
        iv: Iv,
        key_material: &ViturKeyMaterial,
        tag: Vec<u8>,
    ) -> Self {
        Self {
            key: DataKey::from_key_material(key, iv, key_material),
            tag,
        }
    }
}

impl Deref for DataKeyWithTag {
    type Target = DataKey;

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}
