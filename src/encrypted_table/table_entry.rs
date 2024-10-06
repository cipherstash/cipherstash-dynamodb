use super::{table_attribute::TableAttribute, table_attributes::TableAttributes};

// FIXME: Clean this up
// FIXME: Can we remove the Clone and Debug?
//#[skip_serializing_none]
#[derive(Debug, Clone)]
pub struct TableEntry {
    pub(crate) pk: String,
    pub(crate) sk: String,
    pub(crate) term: Option<Vec<u8>>,
    pub(crate) attributes: TableAttributes,
}

impl TableEntry {
    pub fn new(pk: String, sk: String) -> Self {
        Self {
            pk,
            sk,
            term: None,
            attributes: TableAttributes::new(),
        }
    }

    pub fn new_with_attributes(
        pk: String,
        sk: String,
        term: Option<Vec<u8>>,
        attributes: TableAttributes,
    ) -> Self {
        Self {
            pk,
            sk,
            term,
            attributes,
        }
    }

    pub fn add_attribute(&mut self, k: impl Into<String>, v: TableAttribute) {
        self.attributes.insert(k.into(), v);
    }
}
