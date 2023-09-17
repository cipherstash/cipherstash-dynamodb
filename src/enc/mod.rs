use std::collections::HashMap;
use crate::Plaintext;

pub trait EncryptedRecord: crate::target::DynamoTarget {
    fn partition_key(&self) -> String;
    fn attributes(&self) -> HashMap<String, Plaintext>;
}