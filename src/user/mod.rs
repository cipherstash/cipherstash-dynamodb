use std::sync::Arc;

use aws_sdk_dynamodb::Client;
use cipherstash_client::{
    schema::{column::{Tokenizer, Index}, ColumnConfig},
    encryption::{Encryption, Plaintext},
    config::{console_config::ConsoleConfig, vitur_config::ViturConfig},
    vitur::Vitur,
    credentials::{auto_refresh::AutoRefresh, vitur_credentials::ViturCredentials},
};

use crate::dict::DynamoDict;

pub struct User {
    id: String,
    name: String,
}

impl User {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self { id: id.into(), name: name.into() }
    }
}

pub struct Manager<'c> {
    db: &'c Client,
    cipher: Arc<Encryption<AutoRefresh<ViturCredentials>>>,
    dictionary: DynamoDict<'c>,
}

// TODO: impl CipherStash::Searchable (or something)
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

        let dictionary = DynamoDict::init(&db, dataset_config.index_root_key);

        Self { db, cipher, dictionary }
    }

    pub async fn put(self, user: &User) {
        // TODO: Load from Vitur config
        let index_type = Index::new_match().index_type;

        let _index_term = self.cipher.index_with_dictionary(
            &Plaintext::Utf8Str(Some(user.name.to_string())),
            &index_type,
            "name",
            &user.id,
            self.dictionary
        ).await.unwrap();

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