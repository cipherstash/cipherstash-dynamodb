use aws_sdk_dynamodb::{Client, types::{AttributeValue}, primitives::Blob};
use hmac::{Hmac, Mac};
use serde_dynamo::{from_item, to_item};
use sha2::Sha256;
use async_trait::async_trait;
use cipherstash_client::encryption::{Dictionary, DictEntry};

use crate::Key;
type HmacSha256 = Hmac<Sha256>;


pub struct DynamoDict<'c> {
    client: &'c Client,
    key: Key,
}

#[async_trait]
impl<'c> Dictionary for DynamoDict<'c> {
    async fn entry<T, S>(&self, plaintext: T, scope: S) -> DictEntry
        where
            T: Sync + Send + AsRef<[u8]>,
            S: Sync + Send + AsRef<[u8]>
    {
        let term_key = hmac(&self.key, plaintext, scope);
        self.add_term(term_key).await
    }

    // TODO: We probably want to implement entries as well so we can do a bulk op
}

impl<'c> DynamoDict<'c> {
    pub fn init(client: &'c Client, key: Key) -> Self {
        Self { client, key }
    }

    async fn get_dict_entry(&self, term: &[u8]) -> Result<Option<DictEntry>, serde_dynamo::Error> {
        let entry = self
            .client
            .get_item()
            .key("term_key", AttributeValue::B(Blob::new(term.to_vec())))
            .table_name("dict")
            .send()
            .await
            //.map_err(|e| PersistenceError::AdapterError(e.to_string()))?
            .expect("Get to succeed");

        entry.item.map(|de| from_item(de)).transpose()
    }

    // TODO: TermKey type
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

   
}

fn hmac<I: AsRef<[u8]>, S: AsRef<[u8]>>(key: &Key, input: I, scope: S) -> Vec<u8> { // TODO: Use the vec that works on the stack
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(scope.as_ref());
    mac.update(input.as_ref());
    mac.finalize().into_bytes()[0..8].to_vec()
}


  // IDEA: To handle skip lists we may want to keep 2 counters
    // 1. A term counter so we can fetch N postings for that term in a batch
    // 2. A global dictionary counter so that we can skip ahead if needed
    // The global counter would maintain a form of universal ordering
    /*pub async fn query(&self, term_str: &str) -> Vec<String> {
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
    }*/