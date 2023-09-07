use std::collections::HashMap;
use serde_with::skip_serializing_none;

use aws_sdk_dynamodb::{
    types::{AttributeValue, Put, TransactWriteItem},
    Client,
};
use cipherstash_client::{
    config::{console_config::ConsoleConfig, vitur_config::ViturConfig},
    credentials::{auto_refresh::AutoRefresh, vitur_credentials::{ViturCredentials, ViturToken}, Credentials},
    encryption::{Encryption, IndexTerm, Plaintext, Posting},
    schema::{column::{Index, IndexType, TokenFilter, Tokenizer}, TableConfig},
    vitur::{Vitur, DatasetConfigWithIndexRootKey},
};
use serde::{Deserialize, Serialize};
use serde_dynamo::{from_items, to_item};

use crate::dict::DynamoDict;

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

impl EncryptedRecord for User {
    // TODO: These 2 methods should return a plaintext and an index type for how to process them
    fn partition_key(&self) -> String {
        //self.partition_key.to_vec()
        // TODO: Include the type_name in the value that gets hashed/encrypted
        self.email.to_string()
    }

    fn sort_key(&self) -> String {
        "user".to_string()
    }

    fn type_name() -> &'static str {
        "users"
    }

    fn plaintext_targets(&self, config: &TableConfig) -> HashMap<String, Plaintext> {
        HashMap::from([
            ("name".to_string(), Plaintext::from(self.name.to_string()))
        ])
    }
}

async fn encrypt<E, C>(target: &E, cipher: &Encryption<C>, config: &TableConfig) -> Vec<TableEntry>
where
    E: EncryptedRecord,
    C: Credentials<Token = ViturToken>
{
    let plaintexts = target.plaintext_targets(config);
    // TODO: Maybe use a wrapper type?
    let mut attributes: HashMap<String, String> = Default::default();
    for (name, plaintext) in plaintexts.iter() {
        // TODO: Use the bulk encrypt
        if let Some(ct) = cipher
            .encrypt_single(&plaintext, &format!("{}#{}", E::type_name(), name))
            .await.unwrap() {
                attributes.insert(name.to_string(), ct);
        }
    }

    let root = TableEntry {
        pk: target.partition_key(),
        sk: target.sort_key(),
        term: None,
        field: None,
        attributes
    };

    // TODO: Indexes

    vec![root]
}

pub trait EncryptedRecord {
    fn type_name() -> &'static str;
    fn partition_key(&self) -> String;
    fn sort_key(&self) -> String;

    fn plaintext_targets(&self, config: &TableConfig) -> HashMap<String, Plaintext>;
    //fn indexes(&self) -> 
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct TableEntry {
    // Everything hex strings for now
    //#[serde(with = "hex")]
    //pk: Vec<u8>,
    pk: String,
    //#[serde(with = "hex")]
    sk: String,
    //#[serde(with = "hex")]
    term: Option<String>, // TODO: Make term optional

    /// Optional field specified by postings
    //field: Option<String>,
    field: Option<String>,

    // Remaining fields
    #[serde(flatten)]
    attributes: HashMap<String, String>, // TODO: We will need to handle other types for plaintext values
}

/*impl TableEntry {
    fn new_posting(posting: Posting, attributes: HashMap<Vec<u8>, Vec<u8>>) -> Self {
        Self {
            pk: attributes.partition_key(),
            // TODO: we need to prefix this with plaintext field name too so we can delete these later
            sk: posting.field,
            term: posting.term,
            attributes,
            field: "name".to_string(), // TODO: Don't hard code the name
            _phantom: PhantomData,
        }
    }

    fn new(attributes: &A) -> Self {
        Self {
            pk: attributes.partition_key(),
            sk: attributes.sort_key(),
            term: vec![0, 0], // FIXME: term should be optional
            attributes: attributes.clone(),
            field: "base".to_string(),
            _phantom: PhantomData,
        }
    }
}*/

impl User {
    pub fn new(email: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            name: name.into(),
        }
    }
}

pub struct Manager<'c> {
    db: &'c Client,
    cipher: Box<Encryption<AutoRefresh<ViturCredentials>>>,
    dataset_config: DatasetConfigWithIndexRootKey,
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

        let dataset_config = vitur_client.load_dataset_config().await.unwrap();

        let cipher = Box::new(Encryption::new(dataset_config.index_root_key, vitur_client));

        // TODO: Keep the dictionary in an Arc and implement the trait for the Arc?
        let dictionary = DynamoDict::init(&db, dataset_config.index_root_key);

        Self {
            db,
            cipher,
            dictionary,
            dataset_config
        }
    }

    pub async fn query(self, field_name: &str, query: &str) -> Vec<User> {
        // TODO: Load from Vitur config
        let index_type = Index::new_match().index_type;
        if let IndexTerm::PostingArrayQuery(terms) = self
            .cipher
            .query_with_dictionary(
                &Plaintext::Utf8Str(Some(query.to_string())),
                &index_type,
                "name",
                &self.dictionary,
            )
            .await
            .unwrap()
        {
            let terms_list: String = terms
                .iter()
                .enumerate()
                .map(|(i, _)| format!(":t{i}"))
                .collect::<Vec<String>>()
                .join(",");

            let mut query = self
                .db
                .query()
                .table_name("users")
                .index_name("TermIndex")
                .key_condition_expression("field = :field")
                .expression_attribute_values(":field", AttributeValue::S(field_name.to_string()))
                .filter_expression(format!("term in ({terms_list})"));

            for (i, term) in terms.iter().enumerate() {
                query = query.expression_attribute_values(
                    format!(":t{i}"),
                    AttributeValue::S(hex::encode(term)),
                );
            }

            let result = query.send().await.unwrap();

            let table_entries: Vec<TableEntry> =
                from_items(result.items.unwrap()).unwrap();
            
            let mut results: Vec<User> = Vec::with_capacity(table_entries.len());

            for te in table_entries.into_iter() {
                // TODO: Bulk decrypt
                //results.push(te.attributes.decrypt(&self.cipher).await);
            }

            results
            
        } else {
            unreachable!()
        }
    }

    // TODO: get, update, delete

    // TODO: Encrypt all fields on the type (some sort of derive macro may be needed)
    // TODO: Encrypt the source values
    pub async fn put(&self, user: User) {
        let table_config = self
            .dataset_config
            .config
            .get_table(&User::type_name())
            .expect("No config found for type");

        // TODO: The default indexer doesn't downcase!
        // FIXME: There is an API problem here, the indexing code should be on the match types
        // and we should have a DictIndex or something
        let index_type = IndexType::Match {
            tokenizer: Tokenizer::EdgeGram {
                min_length: 3,
                max_length: 10,
            },
            token_filters: vec![TokenFilter::Downcase],
            k: 6,
            m: 2048,
            include_original: false,
        };

        // TODO: Create an index function on the EncryptedType
        // Indexes don't need all attributes
        if let IndexTerm::PostingArray(postings) = self
            .cipher
            .index_with_dictionary(
                &Plaintext::Utf8Str(Some(user.name.to_string())),
                &index_type,
                "name",
                &user.name,
                &self.dictionary,
            )
            .await
            .unwrap()
        {
            let mut items: Vec<TransactWriteItem> = Vec::with_capacity(postings.len() + 1);


            // TODO: Delete old postings
            /*for posting in postings.into_iter() {
                let item = TableEntry::new_posting(posting, &enc_user);

                items.push(
                    TransactWriteItem::builder()
                        .put(
                            Put::builder()
                                .table_name("users")
                                .set_item(Some(to_item(item).unwrap()))
                                .build(),
                        )
                        .build(),
                );
            }*/

            /*let item = TableEntry::new(&enc_user);

            items.push(
                TransactWriteItem::builder()
                    .put(
                        Put::builder()
                            .table_name("users")
                            .set_item(Some(to_item(item).unwrap()))
                            .build(),
                    )
                    .build(),
            );

            self.db
                .transact_write_items()
                .set_transact_items(Some(items))
                .send()
                .await
                .unwrap();*/
        } else {
            unreachable!()
        }

        // TODO: Use a combinator
        let table_entries = encrypt(&user, &self.cipher, table_config).await;
        let mut items: Vec<TransactWriteItem> = Vec::with_capacity(table_entries.len());
        for entry in table_entries.into_iter() {
            items.push(
                TransactWriteItem::builder()
                    .put(
                        Put::builder()
                            .table_name("users") // TODO: Make this an arg to the manager
                            .set_item(Some(to_item(entry).unwrap()))
                            .build(),
                    )
                    .build(),
            );
        }

        self.db
                .transact_write_items()
                .set_transact_items(Some(items))
                .send()
                .await
                .unwrap();

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
