use std::collections::HashMap;

use aes::{Aes128, cipher::generic_array::GenericArray, Block};
use aws_sdk_dynamodb::{Client, types::{AttributeValue, KeysAndAttributes}, primitives::Blob};
use hmac::{Hmac, Mac};
use serde::{Serialize, Deserialize};
use serde_dynamo::{from_item, to_item, from_items};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;
type Key = [u8; 32];

/* 
    Alternative 1:  ID for Dynamo (we should test it).
    Keep each term in a partition (partition key) but hide term frequency
    by creating a block of postings.
    Dynamo queries would just fetch the entire block for the term.
    For this to be secure, the IDs would need to be encrypted, too.
    Otherwise, it would be obvious which postings in the block were padding terms.

    Alternative 2: Use the first x bits of the term as the partition key.
    We might have to experiment with the size of x to manage the size of the partitions
    and the risk of leaking frequency.

    We want to keep a partition smaller than 1MB (AFAICT).

    For example, the set of all possible trigrams is 36^3 (ignoring case).
    Only a subset of those will be commonly seen in text.
    Basically we want to flatten the histogram.

    Alternative 3: A combination
    The dictionary itself won't be massive and we only need to get a few items at a time.
    For postings, we use a hash and a count to generate the terms for N values at a time.
    That is, all N values have the same term.
    This would be the partition key.
    So long as N stays relatively small, it won't leak term frequency.

    There is a global counter, c.
    When a term is created, 

*/

pub struct Dict<'c> {
    client: &'c Client,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DictEntry {
    #[serde(with = "serde_bytes")]
    term: Vec<u8>,
    // TODO: Encrypt
    count: u32,
    salt: [u8; 16],
    partition_size: u16,
}

const PARTITION_SIZE: u16 = 10;

impl DictEntry {
    fn new(term: Vec<u8>) -> Self {
        Self {
            term,
            count: 0,
            partition_size: 0,
            // Sentinel value to start
            salt: [0; 16],
        }
    }

    fn incr(mut self) -> Self {
        self.count += 1;
        if self.partition_size > PARTITION_SIZE {
            self.partition_size = 0;
            // Encrypt the salt
            // TODO: Which key?
            self.salt = aes(&Default::default(), &self.salt);
        }
        self
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Posting {
    #[serde(with = "serde_bytes")]
    term: Vec<u8>,
    doc_id: String, // ref?
}

impl Posting {
    fn from_dict_entry(key: &Key, de: &DictEntry, doc_id: impl Into<String>) -> Self {
        // TODO: term needs to be the partition key
        // TODO: What do we do when a doc ID is deleted?
        // Should there be a compaction process?
        Self {
            term: hmac(key, &de.term, Some(de.salt)),
            doc_id: doc_id.into(),
        }
    }
}

impl<'c> Dict<'c> {
    pub fn init(client: &'c Client) -> Self {
        Self { client }
    }

    pub async fn add(&self, term_str: &str, doc_id: &str) {
        let term = hmac(&Default::default(), term_str, None::<&[u8]>); // TODO: Pass a dict key
        let de = self.add_term(term).await;
        self.add_posting(&de, doc_id).await;
    }

    // IDEA: To handle skip lists we may want to keep 2 counters
    // 1. A term counter so we can fetch N postings for that term in a batch
    // 2. A global dictionary counter so that we can skip ahead if needed
    // The global counter would maintain a form of universal ordering
    pub async fn query(&self, term_str: &str) -> Vec<String> {
        let term = hmac(&Default::default(), term_str, None::<&[u8]>);
        let de = self.get_dict_entry(&term).await.unwrap();
        if de.is_some() {
            let start = de.unwrap().count;
            // TODO: Instead of saturating, we may want to add some random terms
            let mut builder = KeysAndAttributes::builder();
            for c in start.saturating_sub(100)..start { // TODO: Use a combinator
                let term = hmac(&Default::default(), &term, Some(c.to_be_bytes()));
                
                builder = builder.keys(HashMap::from([(
                    "term".to_string(),
                    AttributeValue::B(Blob::new(term)),
                )]))
            }


            let result = self.
                client
                .batch_get_item()
                .request_items(
                    "dict",
                   builder.build(),
                )
                .send()
                .await
                .unwrap();

            let items = result
                .responses()
                .unwrap()
                .get("dict")
                .unwrap();

            // FIXME: The to_vec is bad
            let postings: Vec<Posting> = from_items(items.to_vec()).unwrap();
            postings.iter().map(|p| p.doc_id.to_string()).collect()
        } else {
            vec![]
        }
    }

    async fn get_dict_entry(&self, term: &[u8]) -> Result<Option<DictEntry>, serde_dynamo::Error> {
        let entry = self
            .client
            .get_item()
            .key("term", AttributeValue::B(Blob::new(term.to_vec())))
            .table_name("dict")
            .send()
            .await
            //.map_err(|e| PersistenceError::AdapterError(e.to_string()))?
            .expect("Get to succeed");

        entry.item.map(|de| from_item(de)).transpose()
    }

    async fn add_term(&self, term: Vec<u8>) -> DictEntry {

        let dict_entry = self
            .get_dict_entry(&term)
            .await
            .unwrap()
            .unwrap_or(DictEntry::new(term))
            .incr();

        let new_item = to_item(&dict_entry).unwrap();

        self.client
            .put_item()
            .set_item(Some(new_item))
            .table_name("dict")
            .send()
            .await
            .unwrap();

        dict_entry
    }

    // TODO: Delete the postings for this doc ID first (when adding all terms)
    async fn add_posting(&self, de: &DictEntry, doc_id: &str) {
        let posting = Posting::from_dict_entry(&Default::default(), de, doc_id);
        let item = to_item(posting).unwrap();

        self.client
            .put_item()
            .set_item(Some(item))
            .table_name("dict")
            .send()
            .await
            .unwrap();
    }
}

fn hmac<I: AsRef<[u8]>, S: AsRef<[u8]>>(key: &Key, input: I, salt: Option<S>) -> Vec<u8> { // TODO: Use the vec that works on the stack
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(input.as_ref());
    if let Some(s) = salt {
        mac.update(s.as_ref());
    }
    mac.finalize().into_bytes().to_vec()
}

fn aes(key: &Key, input: &[u8; 16]) -> [u8; 16] {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block = Block::clone_from_slice(input);
    cipher.encrypt_block(&mut block);

    let mut output = [0; 16];
    output.copy_from_slice(&block);
    output
}