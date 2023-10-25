use crate::errors::RecipherError;
use rand::Rng;

pub type Key = [u8; 32];
pub type Iv = [u8; 16];

pub trait GenRandom {
    fn gen_random<R: Rng>(rng: &mut R) -> Result<Self, RecipherError>
    where
        Self: Sized;
}

impl GenRandom for Key {
    fn gen_random<R: Rng>(rng: &mut R) -> Result<Self, RecipherError> {
        let mut k: Self = Default::default();
        rng.try_fill_bytes(&mut k)
            .map_err(|e| RecipherError::RandomizationError(e.to_string()))?;

        Ok(k)
    }
}

impl GenRandom for Iv {
    fn gen_random<R: Rng>(rng: &mut R) -> Result<Self, RecipherError> {
        let mut iv: Self = Default::default();
        rng.try_fill_bytes(&mut iv)
            .map_err(|e| RecipherError::RandomizationError(e.to_string()))?;

        Ok(iv)
    }
}
