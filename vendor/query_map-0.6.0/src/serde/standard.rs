use serde_crate::{
    de::{Error as DeError, MapAccess, Visitor},
    Deserialize, Deserializer,
};

use crate::QueryMap;
use std::{collections::HashMap, fmt, sync::Arc};

#[cfg_attr(feature = "serde", derive(Deserialize), serde(crate = "serde_crate"))]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

struct QueryMapVisitor;

impl<'de> Visitor<'de> for QueryMapVisitor {
    type Value = QueryMap;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a QueryMap")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(QueryMap::default())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(QueryMap::default())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(self)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut inner = map
            .size_hint()
            .map_or_else(HashMap::new, HashMap::with_capacity);
        // values may either be a single String or Vec<String>
        // to handle both single and multi value data
        while let Some((key, value)) = map.next_entry::<_, OneOrMany>()? {
            inner.insert(
                key,
                match value {
                    OneOrMany::One(one) => vec![one],
                    OneOrMany::Many(many) => many,
                },
            );
        }
        Ok(QueryMap(Arc::new(inner)))
    }
}

impl<'de> Deserialize<'de> for QueryMap {
    fn deserialize<D>(deserializer: D) -> Result<QueryMap, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(QueryMapVisitor)
    }
}

/// Deserialize `null` values into optional values
pub fn deserialize_optional<'de, D>(deserializer: D) -> Result<Option<QueryMap>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::deserialize(deserializer)
}

/// Deserialize `null` values into default `QueryMap` objects
pub fn deserialize_empty<'de, D>(deserializer: D) -> Result<QueryMap, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_option(QueryMapVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_null() {
        #[cfg_attr(
            feature = "serde",
            derive(Deserialize, Serialize),
            serde(crate = "serde_crate")
        )]
        struct Test {
            #[serde(deserialize_with = "deserialize_empty")]
            data: QueryMap,
        }

        let json = serde_json::json!({ "data": null });

        let test: Test = serde_json::from_value(json).unwrap();
        assert!(test.data.is_empty());
    }

    #[test]
    fn test_deserialize_missing() {
        #[cfg_attr(
            feature = "serde",
            derive(Deserialize, Serialize),
            serde(crate = "serde_crate")
        )]
        struct Test {
            #[serde(default, deserialize_with = "deserialize_optional")]
            data: Option<QueryMap>,
        }

        let json = serde_json::json!({});

        let test: Test = serde_json::from_value(json).unwrap();
        assert_eq!(None, test.data);

        let json = serde_json::json!({
            "data": {
                "foo": "bar"
            }
        });

        let test: Test = serde_json::from_value(json).unwrap();
        assert!(test.data.is_some());
    }

    #[test]
    fn test_deserialize_single() {
        #[cfg_attr(
            feature = "serde",
            derive(Deserialize, Serialize),
            serde(crate = "serde_crate")
        )]
        struct Test {
            data: QueryMap,
        }

        let json = serde_json::json!({
            "data": {
                "foo": "bar"
            }
        });

        let test: Test = serde_json::from_value(json).unwrap();
        assert_eq!("bar", test.data.first("foo").unwrap());

        let expected = serde_json::json!({
            "data": {
                "foo": ["bar"]
            }
        });

        let reparsed = serde_json::to_value(test).unwrap();
        assert_eq!(expected, reparsed);
    }

    #[test]
    fn test_deserialize_single_with_comma_separated_values() {
        #[cfg_attr(
            feature = "serde",
            derive(Deserialize, Serialize),
            serde(crate = "serde_crate")
        )]
        struct Test {
            data: QueryMap,
        }

        let json = serde_json::json!({
            "data": {
                "foo": "bar,baz"
            }
        });

        let test: Test = serde_json::from_value(json).unwrap();
        assert_eq!("bar,baz", test.data.first("foo").unwrap());

        let expected = serde_json::json!({
            "data": {
                "foo": ["bar,baz"]
            }
        });

        let reparsed = serde_json::to_value(test).unwrap();
        assert_eq!(expected, reparsed);
    }

    #[test]
    fn test_deserialize_vector_single() {
        #[cfg_attr(
            feature = "serde",
            derive(Deserialize, Serialize),
            serde(crate = "serde_crate")
        )]
        struct Test {
            data: QueryMap,
        }

        let json = serde_json::json!({
            "data": {
                "foo": ["bar"]
            }
        });

        let test: Test = serde_json::from_value(json.clone()).unwrap();
        assert_eq!("bar", test.data.first("foo").unwrap());

        let reparsed = serde_json::to_value(test).unwrap();
        assert_eq!(json, reparsed);
    }

    #[test]
    fn test_deserialize_vector_all() {
        #[cfg_attr(
            feature = "serde",
            derive(Deserialize, Serialize),
            serde(crate = "serde_crate")
        )]
        struct Test {
            data: QueryMap,
        }

        let json = serde_json::json!({
            "data": {
                "foo": ["bar", "baz"]
            }
        });

        let test: Test = serde_json::from_value(json.clone()).unwrap();
        assert_eq!("bar", test.data.first("foo").unwrap());
        assert_eq!(vec!["bar", "baz"], test.data.all("foo").unwrap());

        let reparsed = serde_json::to_value(test).unwrap();
        assert_eq!(json, reparsed);
    }
}
