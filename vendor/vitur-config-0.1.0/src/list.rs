use serde::{
    de::{Deserialize, Deserializer, Visitor},
    ser::{Serialize, SerializeSeq},
};
use std::fmt::Debug;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("Cannot insert duplicate entry to list: `{0:?}`")]
pub struct DuplicateEntry<E: ListEntry>(E);

pub trait ListEntry: PartialEq + Debug + Clone {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniqueList<E: ListEntry> {
    items: Vec<E>,
}

impl<E: ListEntry> Default for UniqueList<E> {
    fn default() -> Self {
        Self { items: vec![] }
    }
}

impl<E: ListEntry> UniqueList<E> {
    pub fn new() -> Self {
        Self { items: vec![] }
    }

    pub fn with_capacity(size: usize) -> Self {
        Self {
            items: Vec::with_capacity(size),
        }
    }

    pub fn try_insert(&mut self, entry: E) -> Result<(), DuplicateEntry<E>> {
        if self.has_entry(&entry) {
            Err(DuplicateEntry(entry))
        } else {
            self.items.push(entry);
            Ok(())
        }
    }

    pub fn has_entry<Q>(&self, query: &Q) -> bool
    where
        E: PartialEq<Q>,
    {
        self.get(query).is_some()
    }

    pub fn get<Q>(&self, query: &Q) -> Option<&E>
    where
        E: PartialEq<Q>,
    {
        if let Some(e) = self.items.iter().find(|e: &&E| *e == query) {
            Some(e)
        } else {
            None
        }
    }

    pub fn iter(&self) -> std::slice::Iter<E> {
        self.items.iter()
    }

    pub fn iter_mut(&mut self) -> std::slice::IterMut<E> {
        self.items.iter_mut()
    }
}

impl<E: ListEntry> std::ops::Index<usize> for UniqueList<E> {
    type Output = E;

    fn index(&self, i: usize) -> &Self::Output {
        &self.items[i]
    }
}

impl<E: ListEntry> Serialize for UniqueList<E>
where
    E: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.items.len()))?;

        for element in self.items.iter() {
            seq.serialize_element(element)?;
        }

        seq.end()
    }
}

struct UniqueListDeserializer<E>(std::marker::PhantomData<E>);

impl<E> UniqueListDeserializer<E> {
    fn new() -> Self {
        Self(Default::default())
    }
}

impl<'de, E: ListEntry + Deserialize<'de>> Visitor<'de> for UniqueListDeserializer<E> {
    type Value = UniqueList<E>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a unique list of values")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut list = seq
            .size_hint()
            .map(Self::Value::with_capacity)
            .unwrap_or_else(Self::Value::new);

        while let Some(value) = seq.next_element::<E>()? {
            list.try_insert(value).map_err(serde::de::Error::custom)?;
        }

        Ok(list)
    }
}

impl<'de, E: ListEntry> Deserialize<'de> for UniqueList<E>
where
    E: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(UniqueListDeserializer::<E>::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_str, to_string};

    impl ListEntry for usize {}

    #[derive(Clone, PartialEq, Debug)]
    struct MyEntry(u32, u32);
    impl ListEntry for MyEntry {}

    #[test]
    fn empty_has_key() -> Result<(), Box<dyn std::error::Error>> {
        let list: UniqueList<MyEntry> = UniqueList::new();
        assert!(!list.has_entry(&MyEntry(10, 10)));

        Ok(())
    }

    #[test]
    fn empty_get() -> Result<(), Box<dyn std::error::Error>> {
        let list: UniqueList<MyEntry> = UniqueList::new();
        assert_eq!(list.get(&MyEntry(1, 1)), None);

        Ok(())
    }

    #[test]
    fn insert_dupe() -> Result<(), Box<dyn std::error::Error>> {
        let mut list: UniqueList<MyEntry> = UniqueList::new();
        list.try_insert(MyEntry(10, 10))?;
        assert!(list.try_insert(MyEntry(10, 10)).is_err());

        Ok(())
    }

    #[test]
    fn insert_and_get() -> Result<(), Box<dyn std::error::Error>> {
        let mut list: UniqueList<MyEntry> = UniqueList::new();
        list.try_insert(MyEntry(5, 15))?;
        let result = list.get(&MyEntry(5, 15));
        assert_eq!(result, Some(&MyEntry(5, 15)));

        Ok(())
    }

    #[test]
    fn test_serialise_with_serde() -> Result<(), Box<dyn std::error::Error>> {
        let mut list = UniqueList::<usize>::new();

        list.try_insert(40)?;
        list.try_insert(10)?;
        list.try_insert(20)?;
        list.try_insert(30)?;

        assert_eq!(to_string(&list)?, "[40,10,20,30]");

        Ok(())
    }

    #[test]
    fn test_deserialise_with_serde() -> Result<(), Box<dyn std::error::Error>> {
        let mut list = UniqueList::<usize>::new();
        list.try_insert(40)?;
        list.try_insert(10)?;
        list.try_insert(20)?;
        list.try_insert(30)?;

        assert_eq!(from_str::<UniqueList<usize>>("[40,10,20,30]")?, list);

        Ok(())
    }

    #[test]
    fn test_fail_deserialise_with_serde() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            from_str::<UniqueList<usize>>("[10,10,10,10]")
                .expect_err("Expected de to fail")
                .to_string(),
            "Cannot insert duplicate entry to list: `10` at line 1 column 7"
        );

        Ok(())
    }
}
