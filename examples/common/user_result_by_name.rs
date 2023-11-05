use cryptonamo::{Decryptable, Encryptable, Searchable};

#[derive(Debug, Encryptable, Decryptable, Searchable)]
#[cryptonamo(partition_key = "name")]
pub struct UserResultByName {
    pub name: String,
}
