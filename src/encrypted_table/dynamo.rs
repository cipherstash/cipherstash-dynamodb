use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;

use crate::{traits::PrimaryKeyParts, PkSk};



pub struct DynamoItem(HashMap<String, AttributeValue>);

impl DynamoItem {
    // TODO: How do we handle when a sort key isn't used?
    pub fn new(pksk: PrimaryKeyParts) -> Self {
        let mut item = HashMap::new();
        item.insert("pk".to_string(), AttributeValue::S(pksk.pk));
        item.insert("sk".to_string(), AttributeValue::S(pksk.sk));
        Self(item)
    }
}
