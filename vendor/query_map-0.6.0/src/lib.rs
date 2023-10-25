#![crate_name = "query_map"]
#![deny(clippy::all, clippy::cargo)]
#![warn(missing_docs, nonstandard_style, rust_2018_idioms)]

//!
//!
//! `QueryMap` is a generic wrapper around `HashMap<String, Vec<String>>`
//! to handle different transformations like URL query strings.
//!
//! `QueryMap` can normalize `HashMap` structures with single value elements
//! into structures with value vector elements.
//!
//! # Examples
//!
//! Create a `QueryMap` from a `HashMap`:
//!
//! ```
//! use std::collections::HashMap;
//! use query_map::QueryMap;
//!
//! let mut data = HashMap::new();
//! data.insert("foo".into(), vec!["bar".into()]);
//!
//! let map: QueryMap = QueryMap::from(data);
//! assert_eq!("bar", map.first("foo").unwrap());
//! assert_eq!(None, map.first("bar"));
//! ```
//!
//! Create a `QueryMap` from a Serde Value (requires `serde` feature):
//!
//! ```ignore
//! use query_map::QueryMap;
//! use query_map::serde::standard::*;
//!
//! #[derive(Deserialize)]
//! struct Test {
//!     data: QueryMap,
//! }
//!
//! let json = serde_json::json!({
//!     "data": {
//!         "foo": "bar"
//!     }
//! });
//!
//! let test: Test = serde_json::from_value(json).unwrap();
//! assert_eq!("bar", test.data.first("foo").unwrap());
//! ```
//!
//! Create a `QueryMap` from a query string (requires `url-query` feature):
//!
//! ```
//! use query_map::QueryMap;
//!
//! let data = "foo=bar&baz=quux&foo=qux";
//! let map = data.parse::<QueryMap>().unwrap();
//! let got = map.all("foo").unwrap();
//! assert_eq!(vec!["bar", "qux"], got);
//! ```
//!

use std::{
    collections::{hash_map::Keys, HashMap},
    sync::Arc,
};

#[cfg(feature = "serde")]
pub mod serde;

#[cfg(feature = "serde")]
pub use serde::standard::*;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_derive;

#[cfg(feature = "url-query")]
mod url_query;

#[cfg(feature = "url-query")]
pub use url_query::*;

/// A read-only view into a map of data which may contain multiple values
///
/// Internally data is always represented as many values
#[derive(Default, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize), serde(crate = "serde_crate"))]
pub struct QueryMap(pub(crate) Arc<HashMap<String, Vec<String>>>);

impl QueryMap {
    /// Return the first elelemnt associated with a key
    #[must_use]
    pub fn first(&self, key: &str) -> Option<&str> {
        self.0
            .get(key)
            .and_then(|values| values.first().map(String::as_str))
    }

    /// Return all elements associated with a key
    #[must_use]
    pub fn all(&self, key: &str) -> Option<Vec<&str>> {
        self.0
            .get(key)
            .map(|values| values.iter().map(String::as_str).collect::<Vec<_>>())
    }

    /// Return true if there are no elements in the map
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return an iterator for this map
    #[must_use]
    pub fn iter(&self) -> QueryMapIter<'_> {
        QueryMapIter {
            data: self,
            keys: self.0.keys(),
            current: None,
            next_idx: 0,
        }
    }
}

impl Clone for QueryMap {
    fn clone(&self) -> Self {
        QueryMap(self.0.clone())
    }
}

impl From<HashMap<String, Vec<String>>> for QueryMap {
    fn from(inner: HashMap<String, Vec<String>>) -> Self {
        QueryMap(Arc::new(inner))
    }
}

impl From<HashMap<String, String>> for QueryMap {
    fn from(inner: HashMap<String, String>) -> Self {
        // A `HashMap` cannot have repeated (key, value) pairs
        let map: HashMap<String, Vec<String>> =
            inner.into_iter().map(|(k, v)| (k, vec![v])).collect();
        QueryMap(Arc::new(map))
    }
}

/// A read only reference to the `QueryMap`'s data
pub struct QueryMapIter<'a> {
    data: &'a QueryMap,
    keys: Keys<'a, String, Vec<String>>,
    current: Option<(&'a String, Vec<&'a str>)>,
    next_idx: usize,
}

impl<'a> Iterator for QueryMapIter<'a> {
    type Item = (&'a str, &'a str);

    #[inline]
    fn next(&mut self) -> Option<(&'a str, &'a str)> {
        if self.current.is_none() {
            self.current = self
                .keys
                .next()
                .map(|k| (k, self.data.all(k).unwrap_or_default()));
        };

        let mut reset = false;
        let ret = if let Some((key, values)) = &self.current {
            let value = values[self.next_idx];

            if self.next_idx + 1 < values.len() {
                self.next_idx += 1;
            } else {
                reset = true;
            }

            Some((key.as_str(), value))
        } else {
            None
        };

        if reset {
            self.current = None;
            self.next_idx = 0;
        }

        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn str_map_default_is_empty() {
        let d: QueryMap = QueryMap::default();
        assert!(d.is_empty())
    }

    #[test]
    fn test_map_first() {
        let mut data = HashMap::new();
        data.insert("foo".into(), vec!["bar".into()]);
        let map: QueryMap = QueryMap(data.into());
        assert_eq!("bar", map.first("foo").unwrap());
        assert_eq!(None, map.first("bar"));
    }

    #[test]
    fn test_map_all() {
        let mut data = HashMap::new();
        data.insert("foo".into(), vec!["bar".into(), "baz".into()]);
        let map: QueryMap = QueryMap(data.into());
        let got = map.all("foo").unwrap();
        assert_eq!(vec!["bar", "baz"], got);
        assert_eq!(None, map.all("bar"));
    }

    #[test]
    fn test_map_iter() {
        let mut data = HashMap::new();
        data.insert("foo".into(), vec!["bar".into()]);
        data.insert("baz".into(), vec!["boom".into()]);
        let map: QueryMap = QueryMap(data.into());
        let mut values = map.iter().map(|(_, v)| v).collect::<Vec<_>>();
        values.sort();
        assert_eq!(vec!["bar", "boom"], values);
    }

    #[test]
    fn test_map_from_string_string() {
        let mut data: HashMap<String, String> = HashMap::new();
        data.insert("foo".into(), "bar".into());
        let map: QueryMap = QueryMap::from(data);
        assert_eq!(vec!["bar"], map.all("foo").unwrap());
    }
}
