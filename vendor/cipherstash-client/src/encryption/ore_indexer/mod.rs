use self::conversion::IntoOrePlaintext;
use cipherstash_core::string::orderise_string;
use ore_rs::{scheme::bit2::OreAes128ChaCha20, OreCipher, OreOutput};

use super::{errors::EncryptionError, IndexTerm, Plaintext};
mod conversion;

pub(super) struct OreIndexer {
    cipher: OreAes128ChaCha20,
}

impl OreIndexer {
    pub(super) fn new(root_key: [u8; 32]) -> Result<Self, EncryptionError> {
        let mut k1: [u8; 16] = Default::default();
        let mut k2: [u8; 16] = Default::default();
        k1.copy_from_slice(&root_key[0..16]);
        k2.copy_from_slice(&root_key[16..]);
        Ok(Self {
            cipher: OreCipher::init(&k1, &k2)?,
        })
    }

    /// Encrypts the plaintext with an appropriate ORE scheme.
    /// Strings will return an [`IndexTerm::OreArray`].
    /// All other types will return a [`IndexTerm::OreFull`].
    ///
    pub(super) fn encrypt(&self, value: &Plaintext) -> Result<IndexTerm, EncryptionError> {
        match value {
            Plaintext::Utf8Str(Some(s)) => self.encrypt_string(s),
            Plaintext::Utf8Str(None)
            | Plaintext::BigInt(None)
            | Plaintext::Boolean(None)
            | Plaintext::Decimal(None)
            | Plaintext::Float(None)
            | Plaintext::Int(None)
            | Plaintext::NaiveDate(None)
            | Plaintext::SmallInt(None)
            | Plaintext::Timestamp(None) => Ok(IndexTerm::Null),
            other => {
                let ciphertext = other.to_ore().encrypt(&self.cipher)?;
                Ok(IndexTerm::OreFull(ciphertext.to_bytes()))
            }
        }
    }

    pub(super) fn encrypt_for_query(
        &self,
        value: &Plaintext,
    ) -> Result<IndexTerm, EncryptionError> {
        // TODO: Use only the encrypt_left - currently not supported
        // by the pl/pgsql function

        match value {
            Plaintext::Utf8Str(Some(s)) => self.encrypt_string(s),
            Plaintext::Utf8Str(None)
            | Plaintext::BigInt(None)
            | Plaintext::Boolean(None)
            | Plaintext::Decimal(None)
            | Plaintext::Float(None)
            | Plaintext::Int(None)
            | Plaintext::NaiveDate(None)
            | Plaintext::SmallInt(None)
            | Plaintext::Timestamp(None) => Ok(IndexTerm::Null),
            other => {
                let ciphertext = other.to_ore().encrypt(&self.cipher)?;
                Ok(IndexTerm::OreFull(ciphertext.to_bytes()))
            }
        }
    }

    fn encrypt_string(&self, input_str: &str) -> Result<IndexTerm, EncryptionError> {
        use ore_rs::OreEncrypt;

        let ciphertexts = orderise_string(input_str)?
            .into_iter()
            .map(|value| value.encrypt(&self.cipher).map(|ct| ct.to_bytes()))
            .collect::<Result<Vec<Vec<u8>>, _>>()?;

        Ok(IndexTerm::OreArray(ciphertexts))
    }
}
