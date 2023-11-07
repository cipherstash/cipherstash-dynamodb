#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
//! ## Cryptonamo: Encrypted Tables for DynamoDB
//!
//! Based on the CipherStash SDK and ZeroKMS key service, Cryptonamo provides a simple interface for
//! storing and retrieving encrypted data in DynamoDB.
//!
//! ## Usage
//!
//! To use Cryptonamo, you must first create a table in DynamoDB.
//! The table must have a primary key and sort key, both of type String.
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
//!     --global-secondary-indexes "IndexName=TermIndex,KeySchema=[{AttributeName=term,KeyType=HASH},{AttributeName=pk,KeyType=RANGE}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=5,WriteCapacityUnits=5}"
//! ```
//!
//! See below for more information on schema design for Cryptonamo tables.
//!
//! ### Annotating a Cryptanomo Type
//!
//! To use Cryptonamo, you must first annotate a struct with the `Cryptonamo` derive macro.
//!
//! ```rust
//! use cryptonamo::Cryptonamo;
//!
//! #[derive(Cryptonamo)]
//! #[cryptonamo(partition_key = "email")]
//! struct User {
//!     name: String,
//!     email: String,
//! }
//! ```
//!
//! The `Cryptonamo` derive macro will generate implementations of the following traits:
//!
//! * `Cryptonamo` - a top-level trait that sets up the table name and partition key
//! * `DecryptedRecord` - a trait that allows you to decrypt a record from DynamoDB
//! * `EncryptedRecord` - a trait that allows you to encrypt a record for storage in DynamoDB
//! * `SearchableRecord` - a trait that allows you to search for records in DynamoDB
//!
//! The above example is the minimum required to use Cryptonamo however you can expand capabilities via several macros.
//!
//! ### Controlling Encryption
//!
//! By default, all fields on a `Cryptanomo` type are encrypted and stored in the index.
//! To store a field as a plaintext, use the `plaintext` attribute:
//!
//! ```rust
//! use cryptonamo::Cryptonamo;
//!
//! #[derive(Cryptonamo)]
//! #[cryptonamo(partition_key = "email")]
//! struct User {
//!     email: String,
//!     name: String,
//!
//!     #[cryptonamo(plaintext)]
//!     not_sensitive: String,
//! }
//! ```
//!
//! Most basic rust types will work automatically but you can implement a conversion trait for [Plaintext] to support custom types.
//!
//! ```rust
//! impl From<MyType> for Plaintext {
//!     fn from(t: MyType) -> Self {
//!         t.as_bytes().into()
//!     }
//! }
//! ```
//!
//! If you don't want a field stored in the the database at all, you can annotate the field with `#[cryptonamo(skip)]`.
//!
//!```rust
//! use cryptonamo::Cryptonamo;
//!
//! #[derive(Cryptonamo)]
//! #[cryptonamo(partition_key = "email")]
//! struct User {
//!     email: String,
//!     name: String,
//!
//!     #[cryptonamo(skip)]
//!     not_required: String,
//! }
//! ```
//!
//! ### Sort keys
//!
//! Cryptanomo requires every record to have a sort key and it derives it automatically based on the name of the struct.
//! However, if you want to specify your own, you can use the `sort_key_prefix` attribute:
//!
//!```rust
//! use cryptonamo::Cryptonamo;
//!
//! #[derive(Cryptonamo)]
//! #[cryptonamo(partition_key = "email")]
//! #[cryptonamo(sort_key_prefix = "user")]
//! struct User {
//!     name: String,
//!
//!     #[cryptonamo(skip)]
//!     not_required: String,
//! }
//! ```
//! Note that you can `skip` the partition key as well.
//! In this case, the data won't be stored as an attribute table but a hash of the value will be used for the `pk` value.
//!
//! ## Indexing
//!
//! Cryptanomo supports indexing of encrypted fields for searching.
//! Exact, prefix and compound match types are all supported.
//! To index a field, use the `query` attribute:
//!
//! ```rust
//! use cryptonamo::Cryptonamo;
//!
//! #[derive(Cryptonamo)]
//! #[cryptonamo(partition_key = "email")]
//! struct User {
//!     #[cryptonamo(query = "exact")]
//!     email: String,
//!     
//!    #[cryptonamo(query = "prefix")]
//!     name: String,
//! }
//! ```
//!
//! You can also specify a compound index by using the `compound` attribute.
//! All indexes with the same compound name are combined into a single index.
//!
//! ```rust
//! use cryptonamo::Cryptonamo;
//!
//! #[derive(Cryptonamo)]
//! #[cryptonamo(partition_key = "email")]
//! struct User {
//!     #[cryptonamo(query = "exact", compound = "email#name")]
//!     email: String,
//!     
//!    #[cryptonamo(query = "prefix", compound = "email#name")]
//!     name: String,
//! }
//! ```
//!
//! **NOTE:** Compound indexes defined using the `compound` attribute are not currently working.
//! Check out [SearchableRecord] for more information on how to implement compound indexes.
//!
//! ## Storing and Retrieving Records
//!
//! Interacting with a table in DynamoDB is done via the [EncryptedTable] struct.
//!
//! ```rust
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
//! ```rust
//! # use cryptonamo::{EncryptedTable, Key};
//! #
//! # struct User {
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
//! let user = User::new("dan@coderdan", "Dan Draper");
//! table.put(&user).await?;
//! # }
//! ```
//!
//! To get a record, use the [`EncryptedTable::get`] method:
//!
//! ```rust
//! # use cryptonamo::{EncryptedTable, Key};
//! #
//! # struct User {
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
//! let user: Option<User> = table.get("dan@coderdan.co").await?;
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
//! ```rust
//! # use cryptonamo::{EncryptedTable, Key};
//! #
//! # struct User {
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
//! # }
//! ```
//!
//! ### Querying Records
//!
//! To query records, use the [`EncryptedTable::query`] method which returns a builder:
//!
//! ```rust
//! # use cryptonamo::{EncryptedTable, Key};
//! #
//! # struct User {
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
//! # }
//! ```
//!
//! If you have a compound index defined, Cryptonamo will automatically use it when querying.
//!
//! ```rust
//! # use cryptonamo::{EncryptedTable, Key};
//! #
//! # struct User {
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
//!     .eq("email", "dan@coderdan")
//!     .starts_with("name", "Dan")
//!     .send()
//!     .await?;
//! # }
//! ```
//!
//! ## Table Verticalization
//!
//! Cryptonamo uses a technique called "verticalization" which is a popular approach to storing data in DynamoDB.
//! In practice, this means you can store multiple types in the same table.
//!
//! For example, you might want to store related records to `User` such as `License`.
//!
//! ```rust
//! use cryptonamo::Cryptonamo;
//!
//! #[derive(Cryptonamo)]
//! #[cryptonamo(partition_key = "user_email")]
//! struct License {
//!     #[cryptonamo(query = "exact")]
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
//! ```
//! #[derive(Cryptonamo)]
//! #[cryptonamo(partition_key = "email")]
//! pub struct UserView {
//!     #[cryptonamo(skip)]
//!     email: String,
//!     
//!     #[cryptonamo(query = "prefix")]
//!     name: String,
//! }
//! ```
//!
//! To use the view, you can first `put` and then `query` the value.
//!
//! ```rust
//! let user = UserView::new("dan@coderdan", "Dan Draper");
//! table.put(&user).await?;
//! let results: Vec<UserView> = table
//!     .query()
//!     .starts_with("name", "Dan")
//!     .send()
//!     .await?;
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
//! ```
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
//! - [ ] Support for plaintext types is currently not implemented
//! - [ ] Using the derive macros for compound macros is not working correctly (you can implement the traits directly)
//! - [ ] Sort keys are not currently hashed (and should be)
//!
pub mod crypto;
mod encrypted_table;
mod error;
pub mod traits;
pub use encrypted_table::{EncryptedTable, QueryBuilder};
pub use error::Error;
pub use traits::{Decryptable, Encryptable, Searchable, PrimaryKey, PkSk, Pk};

#[doc(hidden)]
pub use cryptonamo_derive::{Decryptable, Encryptable, Searchable};

// Re-exports
pub use cipherstash_client::encryption;

pub type Key = [u8; 32];
