use cipherstash_client::encryption::DictEntry;
use crate::Key;

/// Query the postings for a given term_key
pub struct QueryPostingsOperation {
    key: Key,
    dict_entry: DictEntry, // TODO: ref
    limit: usize
}

impl QueryPostingsOperation {
    pub fn init(dict_entry: DictEntry, key: Key) -> Self {
        Self { dict_entry, key, limit: 100 }
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }
}