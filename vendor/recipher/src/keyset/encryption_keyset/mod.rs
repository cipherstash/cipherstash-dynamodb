/// KeySet Generation
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

#[cfg(feature = "lockable")]
pub mod lockable;

use crate::{
    errors::RecipherError,
    key::{GenRandom, Key},
    permutation::Permutation,
};

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct EncryptionKeySet {
    pub(crate) p1: Permutation,
    pub(crate) p2: Permutation,
    pub(crate) p3: Permutation,
}

impl EncryptionKeySet {
    pub fn generate() -> Result<Self, RecipherError> {
        let mut rng = ChaCha20Rng::from_entropy();

        let k1: Key = GenRandom::gen_random(&mut rng)?;
        let k2: Key = GenRandom::gen_random(&mut rng)?;
        let k3: Key = GenRandom::gen_random(&mut rng)?;

        let p1 = Permutation::generate(&k1, 16);
        let p2 = Permutation::generate(&k2, 16);
        let p3 = Permutation::generate(&k3, 33); // TODO: Length check!?

        Ok(EncryptionKeySet { p1, p2, p3 })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, RecipherError> {
        serde_cbor::to_vec(self).map_err(RecipherError::Serialization)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecipherError> {
        Ok(serde_cbor::from_slice(bytes)?)
    }
}
