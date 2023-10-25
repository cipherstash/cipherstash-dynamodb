# QueryMap

[![crates.io][crate-image]][crate-link]
[![Documentation][doc-image]][doc-link]
[![Build Status][build-image]][build-link]

QueryMap is a generic wrapper around HashMap<String, Vec<String>>
to handle different transformations like URL query strings.

QueryMap can normalize HashMap structures with single value elements
into structures with value vector elements.

## Installation

```
cargo install query_map
```

## Examples

Create a QueryMap from a HashMap:

```rust
use std::collections::HashMap;
use query_map::QueryMap;

let mut data = HashMap::new();
data.insert("foo".into(), vec!["bar".into()]);

let map: QueryMap = QueryMap::from(data);
assert_eq!("bar", map.first("foo").unwrap());
assert_eq!(None, map.first("bar"));
```

Create a QueryMap from a Serde Value (requires `serde` feature):

```rust
use query_map::QueryMap;
#[derive(Deserialize)]
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
```

Create a QueryMap from a query string (requires `url-query` feature):

```rust
use query_map::QueryMap;

let data = "foo=bar&baz=quux&foo=qux";
let map = data.parse::<QueryMap>().unwrap();
let got = map.all("foo").unwrap();
assert_eq!(vec!["bar", "qux"], got);
```

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/query_map.svg
[crate-link]: https://crates.io/crates/query_map
[doc-image]: https://docs.rs/query_map/badge.svg
[doc-link]: https://docs.rs/query_map
[build-image]: https://github.com/calavera/query-map-rs/workflows/Build/badge.svg
[build-link]: https://github.com/calavera/query-map-rs/actions?query=workflow%3ACI+branch%3Amain