use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::{Put, TransactWriteItem, Update};
use aws_sdk_dynamodb::{Client, types::AttributeValue};
use cipherstash_client::encryption::DictEntry;
use serde::{Serialize, Deserialize};
use serde_dynamo::to_item;
use aes::{Aes256, cipher::generic_array::GenericArray, Block};
use aes::cipher::{BlockEncrypt, KeyInit};
use crate::Key;

#[derive(Debug)]
pub struct AddPostingOperation {
    key: Key,
    dict_entry: DictEntry,
    postings: Vec<Posting>,
}

impl AddPostingOperation {
    pub fn init(dict_entry: DictEntry, key: Key) -> Self {
        Self { dict_entry, postings: vec![], key }
    }

    pub fn add(mut self, doc_id: impl Into<String>) -> Self {
        let posting = Posting::from_dict_entry(&self.key, &self.dict_entry, doc_id);
        self.postings.push(posting);
        Self { dict_entry: self.dict_entry.incr(), ..self }
    }

    pub fn to_transaction_write_items(self) -> Vec<TransactWriteItem> {
        let mut items: Vec<TransactWriteItem> = Vec::with_capacity(self.postings.len() + 1);
        items.push(
            TransactWriteItem::builder()
                .update(
                    Update::builder()
                        .table_name("dict")
                        .key("term_key", AttributeValue::B(Blob::new(self.dict_entry.term_key)))
                        .update_expression("SET ctr = :new_count, size = :new_size")
                        .expression_attribute_values(":new_count", AttributeValue::N(self.dict_entry.ctr.to_string()))
                        .expression_attribute_values(":new_size", AttributeValue::N(self.dict_entry.size.to_string()))
                        .build()
                ).build()
            );

        for posting in self.postings.iter() {
            items.push(
                TransactWriteItem::builder()
                    .put(
                        Put::builder()
                            .table_name("postings")
                            .set_item(Some(to_item(posting).unwrap()))
                            .build()
                    ).build()
            );
        }

        items
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Posting {
    #[serde(with = "serde_bytes")]
    term: Vec<u8>,
    docid: String, // ref?
}

impl Posting {
    fn from_dict_entry(key: &Key, de: &DictEntry, doc_id: impl Into<String>) -> Self {
        Self {
            term: encrypt_posting(key, &de).to_vec(),
            docid: doc_id.into(),
        }
    }
}

pub struct Stack<'c> {
    client: &'c Client,
    dict_entry: DictEntry,
}

impl<'c> Stack<'c> {
    pub(crate) fn init(client: &'c Client, dict_entry: DictEntry) -> Self {
        Self { client, dict_entry }
    }

    // TODO: Delete the postings for this doc ID first (when adding all terms)
    // TODO: This should be on the posting type (or we just create a "Stack type")
    // FIXME: This also needs to increment the dict counter
    pub async fn add_posting(&self, doc_id: &str) {
        let posting = Posting::from_dict_entry(&Default::default(), &self.dict_entry, doc_id);
        let item = to_item(posting).unwrap();

        self.client
            .put_item()
            .set_item(Some(item))
            .table_name("postings")
            .send()
            .await
            .unwrap();
    }

    pub async fn get_posting(&self, doc_id: impl Into<String>) {
        let req = self.
            client
            .query()
            .table_name("postings")
            .index_name("DocIDIndex")
            .key_condition_expression("docid = :d")
            .expression_attribute_values(
                ":d",
                AttributeValue::S(doc_id.into()),
            )
            .send()
            .await
            .unwrap();

        dbg!(req.items);

    }
}

// TODO: This should be a method on dict_entry
fn encrypt_posting(key: &Key, dict_entry: &DictEntry) -> [u8; 16] {
    // FIXME: The term_key should be a static array but right now that breaks serde_dynamo serialization
    assert!(dict_entry.term_key.len() == 8);
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut block = Block::default();
    block[0..8].copy_from_slice(&dict_entry.term_key);
    block[8..].copy_from_slice(&dict_entry.ctr.to_be_bytes());
    cipher.encrypt_block(&mut block);

    let mut output = [0; 16];
    output.copy_from_slice(&block);
    output
}