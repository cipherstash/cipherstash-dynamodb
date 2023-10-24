use std::{collections::HashMap, fmt::Debug};
use crate::{Plaintext, ComposableIndex, ComposablePlaintext};

pub trait Cryptonamo: Debug {
    // TODO: Add a function indicating that the root should be stored
    fn type_name() -> &'static str;
    fn partition_key(&self) -> String;
}

// These are analogous to serde (rename to Encrypt and Decrypt)
pub trait EncryptedRecord: Cryptonamo + Sized {
    fn protected_attributes(&self) -> HashMap<&'static str, Plaintext>;
    
    fn plaintext_attributes(&self) -> HashMap<&'static str, Plaintext> {
        HashMap::default()
    }
}

pub trait SearchableRecord: EncryptedRecord {
    #[allow(unused_variables)]
    fn attribute_for_index(&self, index_name: &str) -> Option<ComposablePlaintext> {
        None
    }

    fn protected_indexes() -> Vec<&'static str> {
        vec![]
    }

    #[allow(unused_variables)]
    fn index_by_name(name: &str) -> Option<Box<dyn ComposableIndex>> {
        None
    }
}

pub trait DecryptedRecord: Cryptonamo {
    fn from_attributes(attributes: HashMap<String, Plaintext>) -> Self;
}
