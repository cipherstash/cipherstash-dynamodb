use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::text::TokenFilter;

use super::{errors::EncryptionError, plaintext::Plaintext, IndexTerm};

type HmacSha256 = Hmac<Sha256>;

pub struct UniqueIndexer {
    index_key: [u8; 32],
    token_filters: Vec<TokenFilter>,
}

impl UniqueIndexer {
    pub fn new(root_key: [u8; 32], token_filters: Vec<TokenFilter>) -> Self {
        // TODO: Later we should derive an index specific key
        Self {
            index_key: root_key,
            token_filters: token_filters.into_iter().collect(),
        }
    }

    pub(super) fn create_hmac(&self) -> Result<HmacSha256, EncryptionError> {
        Ok(HmacSha256::new_from_slice(&self.index_key)?)
    }

    pub(super) fn encrypt_into_hmac(
        &self,
        mac: &mut HmacSha256,
        plaintext: &Plaintext,
    ) -> Result<(), EncryptionError> {
        let plaintext_bytes = match plaintext {
            Plaintext::Utf8Str(None)
            | Plaintext::BigInt(None)
            | Plaintext::Boolean(None)
            | Plaintext::Decimal(None)
            | Plaintext::Float(None)
            | Plaintext::Int(None)
            | Plaintext::NaiveDate(None)
            | Plaintext::SmallInt(None)
            | Plaintext::Timestamp(None) => return Ok(()),

            Plaintext::Utf8Str(Some(utf_str)) => {
                let filtered_string = self
                    .token_filters
                    .iter()
                    .fold(utf_str.to_string(), |s, filter| filter.process_single(s));
                let plaintext = Plaintext::Utf8Str(Some(filtered_string));
                plaintext.to_vec()
            }

            x => x.to_vec(),
        };

        mac.update(&plaintext_bytes);

        Ok(())
    }

    pub(super) fn encrypt(&self, plaintext: &Plaintext) -> Result<IndexTerm, EncryptionError> {
        if plaintext.is_null() {
            Ok(IndexTerm::Null)
        } else {
            let mut mac = self.create_hmac()?;
            self.encrypt_into_hmac(&mut mac, plaintext)?;
            Ok(IndexTerm::Binary(mac.finalize().into_bytes().to_vec()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_case_insensitive_compare() {
        let indexer = UniqueIndexer::new([1; 32], vec![TokenFilter::Downcase]);

        let first = indexer
            .encrypt(&Plaintext::Utf8Str(Some("hello WORLD".into())))
            .expect("Failed to encrypt");
        let second = indexer
            .encrypt(&Plaintext::Utf8Str(Some("HELLO world".into())))
            .expect("Failed to encrypt");

        assert_eq!(first, second);
    }
}
