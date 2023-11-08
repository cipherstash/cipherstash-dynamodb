use cryptonamo::{Decryptable, Encryptable, Searchable};

#[derive(Debug, Encryptable, Decryptable, Searchable)]
pub struct UserResultByName {
    #[partition_key]
    pub name: String,
}
