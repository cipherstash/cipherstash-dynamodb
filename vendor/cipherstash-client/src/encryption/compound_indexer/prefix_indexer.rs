use super::{Accumulator, EncryptionError, Plaintext};
use crate::encryption::text::{process_all_edge_ngrams_raw, TokenFilter};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub(crate) struct PrefixIndexer {
    // TODO: Use SafeVec/Zeroize
    index_key: [u8; 32],
    token_filters: Vec<TokenFilter>,
    min_length: usize,
    max_length: usize,
}

impl PrefixIndexer {
    pub(super) fn new(
        index_key: [u8; 32],
        token_filters: Vec<TokenFilter>,
        min_length: usize,
        max_length: usize,
    ) -> Self {
        Self {
            index_key,
            token_filters,
            min_length,
            max_length,
        }
    }

    pub(super) fn create_hmac(&self) -> Result<HmacSha256, EncryptionError> {
        Ok(HmacSha256::new_from_slice(&self.index_key)?)
    }

    pub(super) fn index_with_salt<S>(
        &self,
        plaintext: &Plaintext,
        salt: S,
    ) -> Result<Accumulator, EncryptionError>
    where
        S: AsRef<[u8]>,
    {
        match plaintext {
            Plaintext::Utf8Str(Some(value)) => {
                let tokens = process_all_edge_ngrams_raw(
                    value.to_string(),
                    self.min_length,
                    self.max_length,
                );

                let terms = self
                    .token_filters
                    .iter()
                    .fold(tokens, |tokens, filter| filter.process(tokens));

                let out = terms
                    .into_iter()
                    .map(|term| {
                        let mut mac = self.create_hmac()?;
                        mac.update(salt.as_ref());
                        mac.update(term.as_bytes());
                        Ok::<Vec<u8>, EncryptionError>(mac.finalize().into_bytes().to_vec())
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(Accumulator::Terms(out))
            }
            _ => Err(EncryptionError::IndexingError(format!(
                "{plaintext:?} is not supported by match indexes"
            ))),
        }
    }

    pub(super) fn query_with_salt<S>(
        &self,
        plaintext: &Plaintext,
        salt: S,
    ) -> Result<Accumulator, EncryptionError>
    where
        S: AsRef<[u8]>,
    {
        match plaintext {
            Plaintext::Utf8Str(Some(value)) => {
                let tokens = vec![value.to_string()];

                let terms = self
                    .token_filters
                    .iter()
                    .fold(tokens, |tokens, filter| filter.process(tokens));

                let term = terms.first().unwrap();

                let mut mac = self.create_hmac()?;
                mac.update(salt.as_ref());
                mac.update(term.as_bytes());

                Ok(Accumulator::Term(mac.finalize().into_bytes().to_vec()))
            }
            _ => Err(EncryptionError::IndexingError(format!(
                "{plaintext:?} is not supported by match indexes"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_term() -> Result<(), Box<dyn std::error::Error>> {
        let indexer = PrefixIndexer::new(
            [0; 32],
            vec![TokenFilter::Downcase],
            2, // min length
            4, // max length
        );

        let result =
            indexer.index_with_salt(&Plaintext::Utf8Str(Some("Hello World".to_string())), &[])?;
        assert_eq!(result.terms().len(), 3);

        Ok(())
    }

    #[test]
    fn test_encrypt_with_salt() -> Result<(), Box<dyn std::error::Error>> {
        let indexer = PrefixIndexer::new(
            [0; 32],
            vec![TokenFilter::Downcase],
            2, // min length
            4, // max length
        );

        let result_no_salt =
            indexer.index_with_salt(&Plaintext::Utf8Str(Some("Hello World".to_string())), &[])?;
        let result_salt = indexer.index_with_salt(
            &Plaintext::Utf8Str(Some("Hello World".to_string())),
            "somesalt".as_bytes().as_ref(),
        )?;

        // No term should be the same when a salt is used
        result_no_salt
            .terms()
            .into_iter()
            .zip(result_salt.terms().into_iter())
            .for_each(|(no_salt, salt)| {
                assert_ne!(no_salt, salt);
            });

        Ok(())
    }

    #[test]
    fn test_query_single_word() -> Result<(), Box<dyn std::error::Error>> {
        let indexer = PrefixIndexer::new(
            [0; 32],
            vec![TokenFilter::Downcase],
            2, // min length
            4, // max length
        );

        let result =
            indexer.query_with_salt(&Plaintext::Utf8Str(Some("Hello".to_string())), &[])?;

        assert_eq!(result.exactly_one()?.term().len(), 32);

        Ok(())
    }
}
