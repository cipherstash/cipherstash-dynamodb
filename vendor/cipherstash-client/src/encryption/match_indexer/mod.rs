use super::text::{char_filter_prefix_and_suffix, TokenFilter, Tokenizer};
use super::{errors::EncryptionError, plaintext::Plaintext, IndexTerm};
use cipherstash_core::bloom_filter::{BloomFilter, BloomFilterOps, FilterKey};

pub(crate) struct MatchIndexer {
    index_key: FilterKey,
    tokenizer: Tokenizer,
    token_filters: Vec<TokenFilter>,
    filter_opts: BloomFilterOps,
}

impl MatchIndexer {
    pub(super) fn new(
        index_key: [u8; 32],
        tokenizer: schema::column::Tokenizer,
        token_filters: Vec<schema::column::TokenFilter>,
        k: usize,
        m: usize,
    ) -> Self {
        // TODO: Derive an index key from the root key and a field ID
        Self {
            index_key,
            tokenizer: tokenizer.into(),
            token_filters: token_filters.into_iter().map(|v| v.into()).collect(),
            filter_opts: BloomFilter::opts()
                .with_filter_size(m as u32)
                .with_hash_function_count(k),
        }
    }

    pub(super) fn encrypt(&self, plaintext: &Plaintext) -> Result<IndexTerm, EncryptionError> {
        match plaintext {
            Plaintext::Utf8Str(Some(value)) => {
                // We call the char filter here, to remove '%' and '_' operators from the beginning and end of the string.
                // This is a short term solution, so the most common of LIKE/ILIKE queries will work without any code changes. (based off what is being used
                // in the demo and current clients codebases)
                //
                // This will cover the below LIKE/ILIKE queries:
                // %value%, %value, value%
                //
                // Until we do a proper implementation, the below LIKE/ILIKE queries are not handled correctly.
                //
                // a%e, a_e, value_, _a%
                //
                // Also, this could mean that plaintext values that genuinely have these chars (%, _) will be stripped of those and
                // returned results will be incomplete.
                //
                // A proper implementation of Like/ILike queries will be handled in this card
                // https://www.notion.so/cipherstash/WIP-Driver-more-robust-LIKE-op-handling-7ccf85c873374fb68ad651816f6bd9f6?pvs=4
                let filtered_output = char_filter_prefix_and_suffix(value.as_str(), &['%', '_']);

                let tokens = self.tokenizer.process(filtered_output);
                let terms = self
                    .token_filters
                    .iter()
                    .fold(tokens, |tokens, filter| filter.process(tokens));
                let mut filter =
                    BloomFilter::new(self.index_key, self.filter_opts).map_err(|e| {
                        EncryptionError::IndexingError(format!(
                            "Bloom Filter init failed with error {e}"
                        ))
                    })?;
                filter.add_terms(terms);

                Ok(IndexTerm::BitMap(filter.into_vec()))
            }
            Plaintext::Utf8Str(None) => Ok(IndexTerm::Null),
            _ => Err(EncryptionError::IndexingError(format!(
                "{plaintext:?} is not supported by match indexes"
            ))),
        }
    }
}

/// Converts a schema (vitur/vitur-config) Tokenizer (which has no impl)
/// into the type used in the `text` module which *is* implemented 😅
impl From<schema::column::Tokenizer> for Tokenizer {
    fn from(value: schema::column::Tokenizer) -> Self {
        match value {
            schema::column::Tokenizer::Standard => Self::Standard,
            schema::column::Tokenizer::Ngram { token_length } => Self::Ngram { token_length },
            schema::column::Tokenizer::EdgeNgram { min_gram, max_gram } => {
                Self::EdgeNgram { min_gram, max_gram }
            }
        }
    }
}

/// Converts a schema (vitur/vitur-config) TokenFilter (which has no impl)
/// into the type used in the `text` module which *is* implemented 😅
impl From<schema::column::TokenFilter> for TokenFilter {
    fn from(value: schema::column::TokenFilter) -> Self {
        match value {
            schema::column::TokenFilter::Downcase => TokenFilter::Downcase,
            schema::column::TokenFilter::Upcase => TokenFilter::Upcase,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schema::{column::Index, ColumnConfig};

    #[test]
    fn test_encrypt_term() -> Result<(), Box<dyn std::error::Error>> {
        let config = ColumnConfig::build("name").add_index(Index::new_match());
        let index = config
            .index_for_operator(&schema::operator::Operator::Like)
            .unwrap();
        if let schema::column::IndexType::Match {
            tokenizer,
            token_filters,
            k,
            m,
            ..
        } = &index.index_type
        {
            let index_key = [0u8; 32];
            let indexer =
                MatchIndexer::new(index_key, tokenizer.clone(), token_filters.to_vec(), *k, *m);
            let term = indexer.encrypt(&"Dan Draper".into())?;
            assert!(matches!(term, IndexTerm::BitMap(_)));
        } else {
            panic!()
        }

        Ok(())
    }
}
