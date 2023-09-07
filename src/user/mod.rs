use std::{sync::Arc, collections::HashMap, marker::PhantomData};
use serde::{Deserialize, Serialize};
use aws_sdk_dynamodb::{Client, types::{Put, TransactWriteItem, KeysAndAttributes, AttributeValue, builders::KeysAndAttributesBuilder}, primitives::Blob};
use cipherstash_client::{
    schema::{column::{Tokenizer, TokenFilter, Index, IndexType}, ColumnConfig},
    encryption::{Encryption, Plaintext, IndexTerm, Posting},
    config::{console_config::ConsoleConfig, vitur_config::ViturConfig},
    vitur::Vitur,
    credentials::{auto_refresh::AutoRefresh, vitur_credentials::ViturCredentials},
};
use serde_dynamo::{to_item, from_items};

use crate::{dict::DynamoDict};

#[derive(Debug)]
pub struct User {
    email: String,
    name: String,
}

// FIXME: Lots of copies going on here! Cow?
// TODO: This should be derived from User
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedUser {
    #[serde(skip)]
    partition_key: Vec<u8>,
    #[serde(with = "hex")]
    email: Vec<u8>,
    #[serde(with = "hex")]
    name: Vec<u8>,
}

impl EncryptedRecord for EncryptedUser {
    type Source = User;

    fn encrypt(user: &User) -> Self {
        // TODO: Do the actual encryption!
        Self {
            partition_key: user.email.as_bytes().to_vec(), // TODO: DE
            email: user.email.as_bytes().to_vec(),
            name: user.email.as_bytes().to_vec()
        }
    }

    fn decrypt(self) -> Self::Source {
        User {
            email: String::from_utf8(self.email).unwrap(),
            name: String::from_utf8(self.name).unwrap(),
        }
    }

    fn partition_key(&self) -> Vec<u8> {
        self.partition_key.to_vec()
    }

    fn sort_key(&self) -> Vec<u8> {
        "user".as_bytes().to_vec()
    }
}

pub trait EncryptedRecord: Clone {
    type Source;
    fn encrypt(input: &Self::Source) -> Self;
    fn decrypt(self) -> Self::Source;

    // TODO: These 2 might make sense in a Dynamo specific trait with the other methods more useful broadly
    fn partition_key(&self) -> Vec<u8>;
    fn sort_key(&self) -> Vec<u8>;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TableEntry<A: EncryptedRecord> {
    #[serde(with = "hex")]
    pk: Vec<u8>,
    #[serde(with = "hex")]
    sk: Vec<u8>,
    #[serde(with = "hex")]
    term: Vec<u8>,

    /// Optional field specified by postings
    //field: Option<String>,
    field: String,

    // Remaining fields
    #[serde(flatten)]
    attributes: A,
}

impl<'d, A: Serialize + Deserialize<'d> + EncryptedRecord> TableEntry<A> {
    fn new_posting(posting: Posting, attributes: &A) -> Self {
        Self {
            pk: attributes.partition_key(),
            // TODO: we need to prefix this with plaintext field name too so we can delete these later
            sk: posting.field,
            term: posting.term,
            attributes: attributes.clone(),
            field: "name".to_string(), // TODO: Don't hard code the name
        }
    }

    fn new(attributes: &A) -> Self {
        Self {
            pk: attributes.partition_key(),
            sk: attributes.sort_key(),
            term: vec![0, 0], // FIXME: term should be optional
            attributes: attributes.clone(),
            field: "base".to_string(),
        }
    }
}

impl User {
    pub fn new(email: impl Into<String>, name: impl Into<String>) -> Self {
        Self { email: email.into(), name: name.into() }
    }
}

pub struct Manager<'c> {
    db: &'c Client,
    cipher: Arc<Encryption<AutoRefresh<ViturCredentials>>>,
    dictionary: DynamoDict<'c>,
}

// TODO: impl CipherStash::Searchable (or something)
// or make it generic/pass a config to it?
// TODO: Instantiate an indexer based on a generic type when initializing the manager
impl<'c> Manager<'c> {
    pub async fn init(db: &'c Client) -> Manager<'c> {
        let console_config = ConsoleConfig::builder().with_env().build().unwrap();
        let vitur_config = ViturConfig::builder()
                            .with_env()
                            .console_config(&console_config)
                            .build_with_client_key()
                            .unwrap();

        let vitur_client = Vitur::new_with_client_key(
            &vitur_config.base_url(),
            AutoRefresh::new(vitur_config.credentials()),
            vitur_config.decryption_log_path().as_deref(),
            vitur_config.client_key(),
        );

        let dataset_config = vitur_client
                            .load_dataset_config()
                            .await
                            .unwrap();

        let cipher =
            Arc::new(Encryption::new(dataset_config.index_root_key, vitur_client));

        // TODO: Keep the dictionary in an Arc and implement the trait for the Arc?
        let dictionary = DynamoDict::init(&db, dataset_config.index_root_key);

        Self { db, cipher, dictionary }
    }

    pub async fn query(self, field_name: &str, query: &str) -> Vec<User> {
        // TODO: Load from Vitur config
        let index_type = Index::new_match().index_type;
        if let IndexTerm::PostingArrayQuery(terms) = self.cipher.query_with_dictionary(
            &Plaintext::Utf8Str(Some(query.to_string())),
            &index_type,
            "name",
            &self.dictionary
        ).await.unwrap() {
            let terms_list: String = terms.iter().enumerate().map(|(i, _)| format!(":t{i}")).collect::<Vec<String>>().join(",");

            let mut query = self
                .db
                .query()
                .table_name("users")
                .index_name("TermIndex")
                .key_condition_expression("field = :field")
                .expression_attribute_values(":field", AttributeValue::S(field_name.to_string()))
                .filter_expression(format!("term in ({terms_list})"));

            for (i, term) in terms.iter().enumerate() {
                query = query.expression_attribute_values(format!(":t{i}"), AttributeValue::S(hex::encode(term)));
            }

            let result = query.send().await.unwrap();

            let table_entries: Vec<TableEntry<EncryptedUser>> = from_items(result.items.unwrap()).unwrap();
            table_entries.into_iter().map(|te| te.attributes.decrypt()).collect()

        } else {
            unreachable!()
        }
    }

    // TODO: get, update, delete

    // TODO: Encrypt all fields on the type (some sort of derive macro may be needed)
    // TODO: Encrypt the source values
    pub async fn put(&self, user: &User) {
        // TODO: Load from Vitur config
        // TODO: The default indexer doesn't downcase!
        // FIXME: There is an API problem here, the indexing code should be on the match types
        // and we should have a DictIndex or something
        let index_type = IndexType::Match {
            tokenizer: Tokenizer::EdgeGram { min_length: 3, max_length: 10 },
            token_filters: vec![TokenFilter::Downcase],
            k: 6, m: 2048, include_original: false
        };

        let enc_user = EncryptedUser::encrypt(user);

        // TODO: Create an index function on the EncryptedType
        // Indexes don't need all attributes
        if let IndexTerm::PostingArray(postings) = self.cipher.index_with_dictionary(
            &Plaintext::Utf8Str(Some(user.name.to_string())),
            &index_type,
            "name",
            &user.name,
            &self.dictionary
        ).await.unwrap() {

            let mut items: Vec<TransactWriteItem> = Vec::with_capacity(postings.len() + 1);

            // TODO: Delete old postings
            for posting in postings.into_iter() {
                let item = TableEntry::new_posting(posting, &enc_user);

                items.push(
                    TransactWriteItem::builder()
                        .put(
                            Put::builder()
                                .table_name("users")
                                .set_item(Some(to_item(item).unwrap()))
                                .build()
                        ).build()
                );
            }

            let item = TableEntry::new(&enc_user);

            items.push(
                TransactWriteItem::builder()
                    .put(
                        Put::builder()
                            .table_name("users")
                            .set_item(Some(to_item(item).unwrap()))
                            .build()
                    ).build()
            );

            self.db
                .transact_write_items()
                .set_transact_items(Some(items))
                .send()
                .await
                .unwrap();

        } else {
            unreachable!()
        }

        //let cipher = Encryption::new(field_key, client);
        // TODO: Use the column config but create a new kind of index for this scheme
        //let config = ColumnConfig::build("name").add_index(Index::new_match());

        // analyse user fields into terms
        // generate term-keys
        // get the terms from the dict (cache them)
        // Generate postings for each term (based on the counts)
        // Generate bloom filters for each term
        // Encrypt each term
        // Put all
        //self
        //    .client
        //    .put_item()


    }

    // query
    // Generate the term keys for the terms
    // Get the dict entries for each
    // Decrypt the dict entries
    // Find the least common dict entry, t
    // For t, generate the first n terms to look up
    // For each of these terms, generate a bloom filter containing all other query terms but using the term posting as the key
}