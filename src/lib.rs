#![doc(html_no_source)]
#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
//! ## Cryptonamo: Encrypted Tables for DynamoDB
//!
//! Based on the CipherStash SDK and ZeroKMS key service, Cryptonamo provides a simple interface for
//! storing and retrieving encrypted data in DynamoDB.
//!
//! ## Usage
//!
//! To use Cryptonamo, you must first create a table in DynamoDB.
//! The table must have a at least partition key, sort key, and term field - all of type String.
//!
//! Cryptonamo also expects a Global Secondary Index called "TermIndex" to exist if you want to
//! search and query against records. This index should project all fields and have a key schema
//! that is a hash on the term attribute.
//!
//! You can use the the `aws` CLI to create a table with an appropriate schema as follows:
//!
//! ```bash
//! aws dynamodb create-table \
//!     --table-name users \
//!     --attribute-definitions \
//!         AttributeName=pk,AttributeType=S \
//!         AttributeName=sk,AttributeType=S \
//!         AttributeName=term,AttributeType=S \
//!     --key-schema \
//!         AttributeName=pk,KeyType=HASH \
//!         AttributeName=sk,KeyType=RANGE \
//!     --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
//!     --global-secondary-indexes "IndexName=TermIndex,KeySchema=[{AttributeName=term,KeyType=HASH}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=5,WriteCapacityUnits=5}"
//! ```
//!
//! See below for more information on schema design for Cryptonamo tables.
//!
//! ### Annotating a Cryptanomo Type
//!
//! To use Cryptonamo, you must first annotate a struct with the `Encryptable`, `Searchable` and
//! `Decryptable` derive macros.
//!
//! ```rust
//! use cryptonamo::{Searchable, Decryptable, Encryptable};
//!
//! #[derive(Debug, Searchable, Decryptable, Encryptable)]
//! struct User {
//!     name: String,
//!     #[partition_key]
//!     email: String,
//! }
//! ```
//!
//! These derive macros will generate implementations for the following traits of the same name:
//!
//! * `Decryptable` - a trait that allows you to decrypt a record from DynamoDB
//! * `Encryptable` - a trait that allows you to encrypt a record for storage in DynamoDB
//! * `Searchable`  - a trait that allows you to search for records in DynamoDB
//!
//! The above example is the minimum required to use Cryptonamo however you can expand capabilities via several macros.
//!
//! ### Controlling Encryption
//!
//! By default, all fields on an annotated struct are stored encrypted in the table.
//!
//! To store a field as a plaintext, you can use the `plaintext` attribute:
//!
//! ```rust
//! use cryptonamo::{Searchable, Decryptable, Encryptable};
//!
//! #[derive(Debug, Searchable, Decryptable, Encryptable)]
//! struct User {
//!     #[partition_key]
//!     email: String,
//!     name: String,
//!
//!     #[cryptonamo(plaintext)]
//!     not_sensitive: String,
//! }
//! ```
//!
//! If you don't want a field stored in the the database at all, you can annotate the field with `#[cryptonamo(skip)]`.
//!
//!```rust
//! use cryptonamo::{Searchable, Encryptable, Decryptable};
//!
//! #[derive(Debug, Searchable, Encryptable, Decryptable)]
//! struct User {
//!     #[partition_key]
//!     email: String,
//!     name: String,
//!
//!     #[cryptonamo(skip)]
//!     not_required: String,
//! }
//! ```
//!
//! If you implement the `Decryptable` trait these skipped fields need to implement `Default`.
//!
//! ### Sort keys
//!
//! Cryptanomo requires every record to have a sort key. By default this will be derived based on the name of the struct.
//! However, if you want to specify your own, you can use the `sort_key_prefix` attribute:
//!
//!```rust
//! use cryptonamo::Encryptable;
//!
//! #[derive(Debug, Encryptable)]
//! #[cryptonamo(sort_key_prefix = "user")]
//! struct User {
//!     #[partition_key]
//!     email: String,
//!     name: String,
//!
//!     #[cryptonamo(skip)]
//!     not_required: String,
//! }
//! ```
//!
//! #### Dynamic Sort keys
//!
//! Cryptonamo also supports specifying the sort key dynamically based on a field on the struct.
//! You can choose the field using the `#[sort_key]` attribute.
//!
//! ```rust
//! use cryptonamo::Encryptable;
//!
//! #[derive(Debug, Encryptable)]
//! struct User {
//!     #[partition_key]
//!     email: String,
//!     #[sort_key]
//!     name: String,
//!
//!     #[cryptonamo(skip)]
//!     not_required: String,
//! }
//! ```
//!
//! Sort keys will contain that value and will be prefixed by the sort key prefix.
//!
//! #### Explicit `pk` and `sk` fields
//!
//! It's common in DynamoDB to use fields on your records called `pk` and `sk` for your partition
//! and sort keys. To support this behaviour these are treated as special keywords in Cryptanomo.
//! If your field contains a `pk` or an `sk` field they must be annotated with the `#[partition_key]` and `#[sort_key]` attributes respectively.
//!
//! ```rust
//! use cryptonamo::Encryptable;
//!
//! #[derive(Debug, Encryptable)]
//! struct User {
//!     #[partition_key]
//!     pk: String,
//!     #[sort_key]
//!     sk: String,
//!
//!     #[cryptonamo(skip)]
//!     not_required: String,
//! }
//! ```
//!
//! ## Indexing
//!
//! Cryptanomo supports indexing of encrypted fields for searching.
//! Exact, prefix and compound match types are currently supported.
//! To index a field, use the `query` attribute:
//!
//! ```rust
//! use cryptonamo::Encryptable;
//!
//! #[derive(Debug, Encryptable)]
//! struct User {
//!     #[cryptonamo(query = "exact")]
//!     #[partition_key]
//!     email: String,
//!     
//!    #[cryptonamo(query = "prefix")]
//!     name: String,
//! }
//! ```
//!
//! You can also specify a compound index by using the `compound` attribute.
//! Indexes with the same name will be combined into the one index.
//!
//! Compound index names must be a combination of field names separated by a #.
//! Fields mentioned in the compound index name that aren't correctly annotated will result in a
//! compilation error.
//!
//! ```rust
//! use cryptonamo::Encryptable;
//!
//! #[derive(Debug, Encryptable)]
//! struct User {
//!     #[cryptonamo(query = "exact", compound = "email#name")]
//!     #[partition_key]
//!     email: String,
//!     
//!    #[cryptonamo(query = "prefix", compound = "email#name")]
//!     name: String,
//! }
//! ```
//!
//! It's also possible to add more than one query attribute to support querying records in multiple
//! different ways.
//!
//!
//! ```rust
//! use cryptonamo::Encryptable;
//!
//! #[derive(Debug, Encryptable)]
//! struct User {
//!     #[cryptonamo(query = "exact")]
//!     #[cryptonamo(query = "exact", compound = "email#name")]
//!     #[partition_key]
//!     email: String,
//!     
//!    #[cryptonamo(query = "prefix")]
//!    #[cryptonamo(query = "exact")]
//!    #[cryptonamo(query = "prefix", compound = "email#name")]
//!     name: String,
//! }
//! ```
//! It's important to note that the more annotations that are added to a field the more index terms that will be generated.
//! Adding too many attributes could result in a proliferation of terms and data.
//!
//! The previous example for example would have the following terms generated:
//!
//! - One term for the exact index on email
//! - One term for the exact index on name
//! - Up to 25 terms for the prefix index on name
//! - Up to 25 terms for the compound index of email and name
//!
//! This would mean a total of 53 records would be inserted.
//!
//! ## Storing and Retrieving Records
//!
//! Interacting with a table in DynamoDB is done via the [EncryptedTable] struct.
//!
//! ```no_run
//! use cryptonamo::{EncryptedTable, Key};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = aws_config::from_env()
//!         .endpoint_url("http://localhost:8000")
//!         .load()
//!         .await;
//!
//!     let client = aws_sdk_dynamodb::Client::new(&config);
//!     let table = EncryptedTable::init(client, "users").await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! All operations on the table are `async` and so you will need a runtime to execute them.
//! In the above example, we connect to a DynamoDB running in a local container and initialize an `EncryptedTable` struct
//! for the "users" table.
//!
//! ### Putting Records
//!
//! To store a record in the table, use the [`EncryptedTable::put`] method:
//!
//! ```no_run
//! # use cryptonamo::{Encryptable, Searchable, Decryptable, EncryptedTable};
//! #
//! # #[derive(Debug, Encryptable, Searchable, Decryptable)]
//! # struct User {
//! #    #[partition_key]
//! #    email: String,
//! #    name: String,
//! # }
//! # impl User {
//! #   fn new(email: impl Into<String>, name: impl Into<String>) -> Self {
//! #       Self { email: email.into(), name: name.into() }
//! #   }
//! # }
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! #    let config = aws_config::from_env()
//! #        .endpoint_url("http://localhost:8000")
//! #        .load()
//! #        .await;
//! #   let client = aws_sdk_dynamodb::Client::new(&config);
//! #   let table = EncryptedTable::init(client, "users").await?;
//! let user = User::new("dan@coderdan", "Dan Draper");
//! table.put(user).await?;
//! # Ok(())
//! # }
//! ```
//!
//! To get a record, use the [`EncryptedTable::get`] method:
//!
//! ```no_run
//! # use cryptonamo::{EncryptedTable, Decryptable, Encryptable, Key};
//! #
//! # #[derive(Debug, Decryptable, Encryptable)]
//! # struct User {
//! #    #[partition_key]
//! #    email: String,
//! #    name: String,
//! # }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! #    let config = aws_config::from_env()
//! #        .endpoint_url("http://localhost:8000")
//! #        .load()
//! #        .await;
//! #   let client = aws_sdk_dynamodb::Client::new(&config);
//! #   let table = EncryptedTable::init(client, "users").await?;
//! let user: Option<User> = table.get("dan@coderdan.co").await?;
//! # Ok(())
//! # }
//! ```
//!
//! The `get` method will return `None` if the record does not exist.
//! It uses type information to decrypt the record and return it as a struct.
//!
//! ### Deleting Records
//!
//! To delete a record, use the [`EncryptedTable::delete`] method:
//!
//! ```no_run
//! # use cryptonamo::{Decryptable, Searchable, Encryptable, EncryptedTable};
//! #
//! # #[derive(Debug, Decryptable, Searchable, Encryptable)]
//! # struct User {
//! #    #[partition_key]
//! #    email: String,
//! #    name: String,
//! # }
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! #    let config = aws_config::from_env()
//! #        .endpoint_url("http://localhost:8000")
//! #        .load()
//! #        .await;
//! #   let client = aws_sdk_dynamodb::Client::new(&config);
//! #   let table = EncryptedTable::init(client, "users").await?;
//! table.delete::<User>("jane@smith.org").await?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Querying Records
//!
//! To query records, use the [`EncryptedTable::query`] method which returns a builder:
//!
//! ```no_run
//! # use cryptonamo::{Searchable, Decryptable, Encryptable, EncryptedTable};
//! #
//! # #[derive(Debug, Decryptable, Searchable, Encryptable)]
//! # struct User {
//! #    #[partition_key]
//! #    email: String,
//! #    name: String,
//! # }
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! #    let config = aws_config::from_env()
//! #        .endpoint_url("http://localhost:8000")
//! #        .load()
//! #        .await;
//! #   let client = aws_sdk_dynamodb::Client::new(&config);
//! #   let table = EncryptedTable::init(client, "users").await?;
//! let results: Vec<User> = table
//!     .query()
//!     .starts_with("name", "Dan")
//!     .send()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! If you have a compound index defined, Cryptonamo will automatically use it when querying.
//!
//! ```no_run
//! # use cryptonamo::{Encryptable, Searchable, Decryptable, EncryptedTable, Key};
//! #
//! # #[derive(Debug, Encryptable, Searchable, Decryptable)]
//! # struct User {
//! #    #[partition_key]
//! #    #[cryptonamo(query = "exact")]
//! #    email: String,
//! #    #[cryptonamo(query = "prefix")]
//! #    name: String,
//! # }
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! #    let config = aws_config::from_env()
//! #        .endpoint_url("http://localhost:8000")
//! #        .load()
//! #        .await;
//! #   let client = aws_sdk_dynamodb::Client::new(&config);
//! #   let table = EncryptedTable::init(client, "users").await?;
//! let results: Vec<User> = table
//!     .query()
//!     .eq("email", "dan@coderdan")
//!     .starts_with("name", "Dan")
//!     .send()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! Note: if you don't have the correct indexes defined this query builder will return a runtime
//! error.
//!
//! ## Table Verticalization
//!
//! Cryptonamo uses a technique called "verticalization" which is a popular approach to storing data in DynamoDB.
//! In practice, this means you can store multiple types in the same table.
//!
//! For example, you might want to store related records to `User` such as `License`.
//!
//! ```rust
//! use cryptonamo::{ Searchable, Encryptable, Decryptable };
//!
//! #[derive(Debug, Searchable, Encryptable, Decryptable)]
//! struct License {
//!     #[cryptonamo(query = "exact")]
//!     #[partition_key]
//!     user_email: String,
//!
//!     #[cryptonamo(plaintext)]
//!     license_type: String,
//!
//!     #[cryptonamo(query = "exact")]
//!     license_number: String,
//! }
//! ```
//!
//! ### Data Views
//!
//! In some cases, these types might simply be a different representation of the same data based on query requirements.
//! For example, you might want to query users by name using a prefix (say for using a "type ahead") but only return the name.
//!
//! ```rust
//! # use cryptonamo::{Searchable, Encryptable, Decryptable};
//!
//! #[derive(Debug, Searchable, Encryptable, Decryptable)]
//! pub struct UserView {
//!     #[cryptonamo(skip)]
//!     #[partition_key]
//!     email: String,
//!     
//!     #[cryptonamo(query = "prefix")]
//!     name: String,
//! }
//! ```
//!
//! To use the view, you can first `put` and then `query` the value.
//!
//! ```no_run
//! # use cryptonamo::{Searchable, Encryptable, Decryptable, EncryptedTable};
//! # #[derive(Debug, Searchable, Encryptable, Decryptable)]
//! # pub struct UserView {
//! #     #[cryptonamo(skip)]
//! #     #[partition_key]
//! #     email: String,
//! #     
//! #     #[cryptonamo(query = "prefix")]
//! #     name: String,
//! # }
//! # impl UserView {
//! #     fn new(email: impl Into<String>, name: impl Into<String>) -> Self {
//! #         Self { email: email.into(), name: name.into() }
//! #     }
//! # }
//! #
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! #    let config = aws_config::from_env()
//! #        .endpoint_url("http://localhost:8000")
//! #        .load()
//! #        .await;
//! #   let client = aws_sdk_dynamodb::Client::new(&config);
//! #   let table = EncryptedTable::init(client, "users").await?;
//! let user = UserView::new("dan@coderdan", "Dan Draper");
//! table.put(user).await?;
//! let results: Vec<UserView> = table
//!     .query()
//!     .starts_with("name", "Dan")
//!     .send()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! So long as the indexes are equivalent, you can mix and match types.
//!
//! ## Internals
//!
//! ### Table Schema
//!
//! Tables created by Cryptonamo have the following schema:
//!
//! ```txt
//! PK        |  SK           |  term                  |   name       |  email   ....
//! ---------------------------------------------------------------------------
//! HMAC(123) |  user         |                        |   Enc(name)  |  Enc(email)
//! HMAC(123) |  user#email   | STE("foo@example.net") |
//! HMAC(123) |  user#name#1  | STE("Mik")             |
//! HMAC(123) |  user#name#2  | STE("Mike")            |
//! HMAC(123) |  user#name#3  | STE("Mike ")           |
//! HMAC(123) |  user#name#4  | STE("Mike R")          |
//! ```
//!
//! `PK` and `SK` are the partition and sort keys respectively.
//! `term` is a global secondary index that is used for searching.
//! And all other attributes are dependent on the type.
//! They may be encrypted or otherwise.
//!
//! ### Source Encryption
//!
//! Cryptonamo uses the CipherStash SDK to encrypt and decrypt data.
//! Values are encypted using a unique key for each record using AES-GCM-SIV with 256-bit keys.
//! Key generation is performed using the ZeroKMS key service and bulk operations are supported making even large queries quite fast.
//!
//! ZeroKMS's root keys are encrypted using AWS KMS and stored in DynamoDB (separate database to the data).
//!
//! When self-hosting ZeroKMS, we recommend running it in different account to your main application workloads.
//!
//! ## Issues and TODO
//!
//! - [ ] Sort keys are not currently hashed (and should be)
//!
pub mod crypto;
mod encrypted_table;
mod error;
pub mod traits;
pub use encrypted_table::{EncryptedTable, QueryBuilder};
pub use error::Error;
pub use traits::{Decryptable, Encryptable, Pk, PkSk, PrimaryKey, Searchable};

#[doc(hidden)]
pub use cryptonamo_derive::{Decryptable, Encryptable, Searchable};

// Re-exports
pub use cipherstash_client::encryption;

pub type Key = [u8; 32];
