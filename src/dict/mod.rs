use crate::Key;
use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue, Client};
use cipherstash_client::encryption::{DictEntry, Dictionary};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_dynamo::{from_item, to_item};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

const DICT_TABLE: &'static str = "users";

pub struct DynamoDict {
    client: Client,
    key: Key,
}

#[derive(Serialize, Deserialize, Debug)]
struct DynamoDictEntry {
    pk: String,
    #[serde(with = "hex")]
    sk: Vec<u8>,
    ctr: u64,
    size: u64,
}

impl DynamoDictEntry {
    // TODO: Make a dict entry trait (and derive) so that users don't have to define this
    fn incr(self) -> Self {
        Self {
            ctr: self.ctr + 1,
            size: self.size + 1,
            ..self
        }
    }
}

impl From<DictEntry> for DynamoDictEntry {
    fn from(dict_entry: DictEntry) -> Self {
        DynamoDictEntry {
            pk: "dict".to_string(),
            sk: dict_entry.term_key,
            ctr: dict_entry.ctr,
            size: dict_entry.size,
        }
    }
}

impl From<DynamoDictEntry> for DictEntry {
    fn from(dynamo_dict_entry: DynamoDictEntry) -> Self {
        DictEntry {
            term_key: dynamo_dict_entry.sk,
            ctr: dynamo_dict_entry.ctr,
            size: dynamo_dict_entry.size,
        }
    }
}

#[async_trait]
impl Dictionary for DynamoDict {
    async fn entry<T, S>(&self, plaintext: T, scope: S) -> DictEntry
    where
        T: Sync + Send + AsRef<[u8]>,
        S: Sync + Send + AsRef<[u8]>,
    {
        let term_key = hmac(&self.key, plaintext, scope);
        self.add_term(&term_key).await
    }

    // TODO: We probably want to implement entries as well so we can do a bulk op
}

impl DynamoDict {
    pub fn init(client: Client, key: Key) -> Self {
        Self { client, key }
    }

    async fn get_dict_entry(&self, term: &[u8]) -> DynamoDictEntry {
        let entry = self
            .client
            .get_item()
            .key("pk", AttributeValue::S("dict".to_string()))
            .key("sk", AttributeValue::S(hex::encode(term)))
            .table_name(DICT_TABLE)
            .send()
            .await
            //.map_err(|e| PersistenceError::AdapterError(e.to_string()))?
            .expect("Get to succeed");

        entry
            .item
            .and_then(|item| {
                let dynamo_item: Result<DynamoDictEntry, _> = from_item(item);
                dynamo_item.ok()
            })
            .unwrap_or(DictEntry::new(term.to_vec()).into())
    }

    // TODO: TermKey type
    async fn add_term(&self, term: &[u8]) -> DictEntry {
        let dict_entry = self.get_dict_entry(&term).await.incr();

        let new_item = to_item(&dict_entry).unwrap();

        self.client
            .put_item()
            .set_item(Some(new_item))
            .table_name(DICT_TABLE)
            .send()
            .await
            .unwrap();

        dict_entry.into()
    }
}

fn hmac<I: AsRef<[u8]>, S: AsRef<[u8]>>(key: &Key, input: I, scope: S) -> Vec<u8> {
    // TODO: Use the vec that works on the stack
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
