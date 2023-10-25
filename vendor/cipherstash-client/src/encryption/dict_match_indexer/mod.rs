pub mod dictionary;
use crate::encryption::dict_match_indexer::dictionary::Posting;
use self::dictionary::Dictionary;
use super::text::{char_filter_prefix_and_suffix, TokenFilter, Tokenizer};
use super::{errors::EncryptionError, plaintext::Plaintext, IndexTerm};
use cipherstash_core::bloom_filter::FilterKey;


pub(crate) struct DictMatchIndexer<'d, D: Dictionary> {
    index_key: FilterKey,
    tokenizer: Tokenizer,
    token_filters: Vec<TokenFilter>,
    dictionary: &'d D,
}

impl<'d, D: Dictionary> DictMatchIndexer<'d, D> {
    pub(super) fn new(
        index_key: [u8; 32],
        tokenizer: schema::column::Tokenizer,
        token_filters: Vec<schema::column::TokenFilter>,
        dictionary: &'d D
    ) -> Self {
        // TODO: Derive an index key from the root key and a field ID
        Self {
            index_key,
            tokenizer: tokenizer.into(),
            token_filters: token_filters.into_iter().map(|v| v.into()).collect(),
            dictionary
        }
    }

    // FIXME: A better pattern here is probably to pass a set of DictEntry to the function
    // and then return the modified DictEntry's along with the postings.
    // This would allow callers to control transaction semantics.
    // It would require separating out the analysis step though (maybe not a bad thing anyway).
    // We may want to consider another return type.
    pub(super) async fn encrypt<C>(
        &self,
        plaintext: &Plaintext,
        column_name: C,
        record_id: &str
    ) -> Result<IndexTerm, EncryptionError>
        where
            C: Sync + Send + AsRef<[u8]>,
    {
        match plaintext {
            Plaintext::Utf8Str(Some(value)) => {
                
                let filtered_output = char_filter_prefix_and_suffix(value.as_str(), &['%', '_']);

                let tokens = self.tokenizer.process(filtered_output);

                let terms = self
                    .token_filters
                    .iter()
                    .fold(tokens, |tokens, filter| filter.process(tokens));

                let mut dict_entries = self
                    .dictionary
                    .entries(&terms, column_name)
                    .await;

                let mut postings: Vec<Posting> = Vec::with_capacity(dict_entries.len());
                for dict_entry in dict_entries.iter_mut() {
                    postings.push(dict_entry.gen_posting(record_id, &self.index_key));
                }

                Ok(IndexTerm::PostingArray(postings))
            }
            Plaintext::Utf8Str(None) => Ok(IndexTerm::Null),

            // TODO: We can handle other types just by MAC'ing them
            _ => Err(EncryptionError::IndexingError(format!(
                "{plaintext:?} is not supported by match indexes"
            ))),
        }
    }

    pub(super) async fn encrypt_for_query<C>(
        &self,
        query: &Plaintext,
        column_name: C,
    ) -> Result<IndexTerm, EncryptionError>
        where
            C: Sync + Send + AsRef<[u8]>,
    {
        match query {
            Plaintext::Utf8Str(Some(value)) => {
                
                let filtered_output = char_filter_prefix_and_suffix(value.as_str(), &['%', '_']);

                let tokens = self.tokenizer.process(filtered_output);

                // FIXME: when querying using an edgegram tokenizer, only the *longest* edgegram should be used
                // This means that the indexer config needs to be different between indexing and querying
                //
                // Why is this only using a single token???
                let tokens = vec![tokens.last().unwrap().to_string()];
                let terms = self
                    .token_filters
                    .iter()
                    .fold(tokens, |tokens, filter| filter.process(tokens));

                
                let dict_entries = self
                    .dictionary
                    .entries(&terms, column_name)
                    .await;

                // Find the dict entry with the lowest frequency
                let base_dict_entry = dict_entries
                    .iter()
                    .min_by(|a, b| a.size.cmp(&b.size))
                    .unwrap(); // TODO: Err (no results)

                // Generate the term stack
                let x = Ok(IndexTerm::PostingArrayQuery(base_dict_entry.gen_term_stack(100, &self.index_key)));

                println!("{x:#?}");

                x
            },
            _ => panic!("Unsupported"), // TODO: Don't panic
        }
    }
}
