use serde_with::skip_serializing_none;
use log::info;
use std::{collections::HashMap, hash::Hash};

use aws_sdk_dynamodb::{
    types::{AttributeValue, Put, TransactWriteItem},
    Client,
};
use cipherstash_client::{
    config::{console_config::ConsoleConfig, vitur_config::ViturConfig},
    credentials::{
        auto_refresh::AutoRefresh,
        vitur_credentials::{ViturCredentials, ViturToken},
        Credentials,
    },
    encryption::{Dictionary, Encryption, IndexTerm, Plaintext, Posting},
    schema::{
        column::{Index, IndexType, TokenFilter, Tokenizer},
        operator::Operator,
        TableConfig,
    },
    vitur::{DatasetConfigWithIndexRootKey, Vitur},
};
use serde::{Deserialize, Serialize};
use serde_dynamo::{aws_sdk_dynamodb_0_29::from_item, from_items, to_item};

use crate::dict::DynamoDict;

#[derive(Debug)]
pub struct User {
    pub email: String,
    pub name: String,
}

#[derive(Debug)]
pub struct UserResultByName {
    pub name: String,
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

    /// TODO: this probably isn't needed
    fn sort_key(&self) -> String {
        "user".to_string()
    }

    fn type_name() -> &'static str {
        "user"
    }

    fn attributes(&self) -> HashMap<String, Plaintext> {
        HashMap::from([
            ("name".to_string(), Plaintext::from(self.name.to_string())),
            ("email".to_string(), Plaintext::from(self.email.to_string())),
        ])
    }
}

impl DecryptedRecord for User {
    fn from_attributes(attributes: HashMap<String, Plaintext>) -> Self {
        Self {
            email: attributes.get("email").unwrap().try_into().unwrap(),
            name: attributes.get("name").unwrap().try_into().unwrap(),
        }
    }
}

impl DecryptedRecord for UserResultByName {
    fn from_attributes(attributes: HashMap<String, Plaintext>) -> Self {
        // TODO: Don't unwrap, make try_from_attributes and return a Result
        UserResultByName {
            name: attributes.get("name").unwrap().try_into().unwrap(),
        }
    }
}

fn index_type_hack(index_type: IndexType) -> IndexType {
    if let IndexType::Match { .. } = index_type {
        IndexType::Match {
            tokenizer: Tokenizer::EdgeGram {
                min_length: 3,
                max_length: 10,
            },
            token_filters: vec![TokenFilter::Downcase],
            include_original: true,
            k: 0,
            m: 0,
        }
    } else {
        index_type
    }
}

fn encrypted_targets<E: EncryptedRecord>(
    target: &E,
    config: &TableConfig,
) -> HashMap<String, Plaintext> {
    target
        .attributes()
        .iter()
        .filter_map(|(attr, plaintext)| {
            config
                .get_column(attr)
                .ok()
                .flatten()
                .and_then(|_| Some((attr.to_string(), plaintext.clone())))
        })
        .collect()
}

/// All index settings that support fuzzy matches
fn encrypted_indexes<E: EncryptedRecord>(
    target: &E,
    config: &TableConfig,
) -> HashMap<String, (Plaintext, IndexType)> {
    target
        .attributes()
        .iter()
        .filter_map(|(attr, plaintext)| {
            config
                .get_column(attr)
                .ok()
                .flatten()
                .and_then(|column| column.index_for_operator(&Operator::ILike))
                // Hack the index type
                .and_then(|index| {
                    Some((
                        attr.to_string(),
                        (plaintext.clone(), index_type_hack(index.index_type.clone())),
                    ))
                })
        })
        .collect()
}

async fn encrypt_query<C, D>(
    query: &Plaintext,
    field_name: &str,
    cipher: &Encryption<C>,
    config: &TableConfig,
    dictionary: &D,
) -> Vec<String>
where
    C: Credentials<Token = ViturToken>,
    D: Dictionary,
{
    let index_type = config
        .get_column(field_name)
        .unwrap()
        .and_then(|c| c.index_for_operator(&Operator::ILike))
        .unwrap()
        .index_type
        .clone();

    if let IndexTerm::PostingArrayQuery(terms) = cipher
        .query_with_dictionary(query, &index_type_hack(index_type), field_name, dictionary)
        .await
        .unwrap()
    {
        terms.into_iter().map(hex::encode).collect()
    } else {
        vec![]
    }
}

async fn decrypt<C>(
    ciphertexts: HashMap<String, String>,
    cipher: &Encryption<C>,
) -> HashMap<String, Plaintext>
where
    C: Credentials<Token = ViturToken>,
{
    let values: Vec<&String> = ciphertexts.values().collect();
    let plaintexts: Vec<Plaintext> = cipher.decrypt(values).await.unwrap();
    ciphertexts
        .into_keys()
        .zip(plaintexts.into_iter())
        .collect()
}

async fn encrypt<E, C, D>(
    target: &E,
    cipher: &Encryption<C>,
    config: &TableConfig,
    dictionary: &D,
) -> Vec<TableEntry>
where
    E: EncryptedRecord,
    C: Credentials<Token = ViturToken>,
    D: Dictionary,
{
    let plaintexts = encrypted_targets(target, config);
    // TODO: Maybe use a wrapper type?
    let mut attributes: HashMap<String, String> = Default::default();
    for (name, plaintext) in plaintexts.iter() {
        // TODO: Use the bulk encrypt
        if let Some(ct) = cipher
            .encrypt_single(&plaintext, &format!("{}#{}", E::type_name(), name))
            .await
            .unwrap()
        {
            attributes.insert(name.to_string(), ct);
        }
    }

    let partition_key = encrypt_partition_key(E::type_name(), &target.partition_key(), cipher);

    let mut table_entries: Vec<TableEntry> = Vec::new();
    table_entries.push(TableEntry {
        pk: partition_key.to_string(),
        sk: target.sort_key(),
        term: None,
        field: None,
        attributes: attributes.clone(),
    });

    // Indexes
    // TODO: Do the indexes first to avoid clones
    for (name, (plaintext, index_type)) in encrypted_indexes(target, config).iter() {
        if let IndexTerm::PostingArray(postings) = cipher
            .index_with_dictionary(plaintext, &index_type, name, &partition_key, dictionary) // TODO: use encrypted partition key
            .await
            .unwrap()
        {
            postings.iter().for_each(|posting| {
                table_entries.push(TableEntry::new_posting(
                    &partition_key,
                    name,
                    posting,
                    attributes.clone(),
                ));
            });
        }
    }

    table_entries
}

fn encrypt_partition_key<C>(type_name: &str, value: &str, cipher: &Encryption<C>) -> String
where
    C: Credentials<Token = ViturToken>,
{
    let plaintext: Plaintext = format!("{type_name}#{value}").into();
    let index_type = Index::new_unique().index_type;
    if let IndexTerm::Binary(bytes) = cipher.index(&plaintext, &index_type).unwrap() {
        hex::encode(bytes)
    } else {
        // NOTE: This highlights an ergonomic issue with the way indexers currently work.
        // When indexing with a Unique indexer, the return type should also be Binary.
        // Because this is wrapped in an Enum, we can't guarantee that we'll get one!
        unreachable!()
    }
}

// TODO: These are analogous to serde (rename to Encrypt and Decrypt)
pub trait EncryptedRecord {
    fn type_name() -> &'static str;
    fn partition_key(&self) -> String;
    fn sort_key(&self) -> String;
    fn attributes(&self) -> HashMap<String, Plaintext>;
}

pub trait DecryptedRecord {
    fn from_attributes(attributes: HashMap<String, Plaintext>) -> Self;
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

impl TableEntry {
    fn new_posting(
        partition_key: impl Into<String>,
        field: impl Into<String>,
        posting: &Posting,
        attributes: HashMap<String, String>,
    ) -> Self {
        let field: String = field.into();
        Self {
            pk: partition_key.into(),
            // We need to prefix this with plaintext field name too so we can delete these later
            sk: format!("{}#{}", &field, hex::encode(&posting.field)),
            term: Some(hex::encode(&posting.term)),
            attributes,
            field: Some(field),
        }
    }

    /*fn new(attributes: &A) -> Self {
        Self {
            pk: attributes.partition_key(),
            sk: attributes.sort_key(),
            term: vec![0, 0], // FIXME: term should be optional
            attributes: attributes.clone(),
            field: "base".to_string(),
            _phantom: PhantomData,
        }
    }*/
}

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
        info!("Initializing...");
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

        info!("Fetching dataset config...");
        let dataset_config = vitur_client.load_dataset_config().await.unwrap();
        let cipher = Box::new(Encryption::new(dataset_config.index_root_key, vitur_client));

        // TODO: Keep the dictionary in an Arc and implement the trait for the Arc?
        let dictionary = DynamoDict::init(&db, dataset_config.index_root_key);

        info!("Ready!");

        Self {
            db,
            cipher,
            dictionary,
            dataset_config,
        }
    }

    pub async fn query<R>(self, field_name: &str, query: &str) -> Vec<R>
    where
        R: DecryptedRecord,
    {
        let table_config = self
            .dataset_config
            .config
            .get_table(&User::type_name())
            .expect("No config found for type");

        let terms = encrypt_query(
            &query.to_string().into(),
            field_name,
            &self.cipher,
            table_config,
            &self.dictionary,
        )
        .await;

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

        for (i, term) in terms.into_iter().enumerate() {
            query = query.expression_attribute_values(format!(":t{i}"), AttributeValue::S(term));
        }

        let result = query.send().await.unwrap();

        let table_entries: Vec<TableEntry> = from_items(result.items.unwrap()).unwrap();

        let mut results: Vec<R> = Vec::with_capacity(table_entries.len());

        // TODO: Bulk Decrypt
        for te in table_entries.into_iter() {
            let attributes = decrypt(te.attributes, &self.cipher).await;
            let record: R = R::from_attributes(attributes);
            results.push(record);
        }

        results
    }

    pub async fn get<T>(&self, pk: &str) -> Option<T>
    where
        T: EncryptedRecord + DecryptedRecord,
    {
        let pk = encrypt_partition_key(T::type_name(), pk, &self.cipher);
        let result = self
            .db
            .get_item()
            .table_name("users")
            .key("pk", AttributeValue::S(pk))
            .key("sk", AttributeValue::S("user".to_string()))
            .send()
            .await
            .unwrap();
        let table_entry: Option<TableEntry> = result.item.and_then(|item| from_item(item).unwrap());

        if let Some(TableEntry { attributes, .. }) = table_entry {
            let attributes = decrypt(attributes, &self.cipher).await;
            Some(T::from_attributes(attributes))
        } else {
            None
        }
    }

    pub async fn put(&self, user: User) {
        let table_config = self
            .dataset_config
            .config
            .get_table(&User::type_name())
            .expect("No config found for type");

        // TODO: Use a combinator
        let table_entries = encrypt(&user, &self.cipher, table_config, &self.dictionary).await;
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
    }
}
