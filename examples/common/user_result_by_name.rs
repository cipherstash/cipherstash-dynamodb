use cryptonamo::Cryptonamo;

#[derive(Debug, Cryptonamo)]
#[cryptonamo(partition_key = "name")]
pub struct UserResultByName {
    pub name: String,
}
