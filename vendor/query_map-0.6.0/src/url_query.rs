use crate::QueryMap;
use std::{
    collections::hash_map::Entry::{Occupied, Vacant},
    collections::HashMap,
};

impl QueryMap {
    /// Convert a `QueryMap` into a URL query string
    pub fn to_query_string(&self) -> String {
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs(self.iter())
            .finish()
    }
}

impl std::str::FromStr for QueryMap {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pairs = form_urlencoded::parse(s.as_bytes()).into_owned();

        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for (k, v) in pairs {
            match map.entry(k) {
                Occupied(entry) => {
                    entry.into_mut().push(v);
                }
                Vacant(entry) => {
                    entry.insert(vec![v]);
                }
            };
        }

        Ok(QueryMap(map.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_map_to_query_string() {
        let data = HashMap::new();
        let map: QueryMap = QueryMap(data.into());
        let query = map.to_query_string();
        assert_eq!("", &query);
    }

    #[test]
    fn test_map_to_query_string() {
        let mut data = HashMap::new();
        data.insert("foo".into(), vec!["bar".into(), "qux".into()]);
        data.insert("baz".into(), vec!["quux".into()]);

        let map: QueryMap = QueryMap(data.into());
        let query = map.to_query_string();
        assert!(query.contains("foo=bar&foo=qux"));
        assert!(query.contains("baz=quux"));
    }

    #[test]
    fn test_map_from_str() {
        let data = "foo=bar&baz=quux&foo=qux";
        let map = data.parse::<QueryMap>().unwrap();

        let got = map.all("foo").unwrap();
        assert_eq!(vec!["bar", "qux"], got);
        let got = map.first("baz").unwrap();
        assert_eq!("quux", got);
    }

    #[test]
    fn test_space_is_encoded_as_plus() {
        let data = "foo=bar+baz";
        let map = data.parse::<QueryMap>().unwrap();

        let got = map.first("foo").unwrap();
        assert_eq!("bar baz", got);

        let query = map.to_query_string();

        assert_eq!(data, query);
    }
}
