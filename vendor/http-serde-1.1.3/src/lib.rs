//! Adds ability to serialize and deserialize types from the [HTTP][http] crate.
//!
//! If you want to serialize `Request` or `Response`, use `into_parts()` and serialize their parts, and then rebuild them using their `Builder`.
//!
//! [serde]: https://lib.rs/serde
//! [http]: https://lib.rs/http
//!
//! ## Usage
//!
//! You must annotate fields with `#[serde(with = "http_serde::<appropriate method>")]`.
//!
//! ```rust
//! # use serde::*;
//! # use http::*;
//! # use http::uri::*;
//! # use ::http_serde;
//! #[derive(Serialize, Deserialize)]
//! struct MyStruct {
//!     #[serde(with = "http_serde::method")]
//!     method: Method,
//!
//!     #[serde(with = "http_serde::status_code")]
//!     status: StatusCode,
//!
//!     #[serde(with = "http_serde::uri")]
//!     uri: Uri,
//!
//!     #[serde(with = "http_serde::header_map")]
//!     headers: HeaderMap,
//!
//!     #[serde(with = "http_serde::authority")]
//!     authority: Authority,
//! }
//! ```

/// For `http::HeaderMap`
///
/// `#[serde(with = "http_serde::header_map")]`
pub mod header_map {
    use http::header::{GetAll, HeaderName};
    use http::{HeaderMap, HeaderValue};
    use serde::de;
    use serde::de::{Deserializer, MapAccess, Unexpected, Visitor};
    use serde::ser::SerializeSeq;
    use serde::{Serialize, Serializer};
    use std::borrow::Cow;
    use std::fmt;

    struct ToSeq<'a>(GetAll<'a, HeaderValue>);

    impl<'a> Serialize for ToSeq<'a> {
        fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
            let count = self.0.iter().count();
            if ser.is_human_readable() {
                if count == 1 {
                    if let Some(v) = self.0.iter().next() {
                        if let Ok(s) = v.to_str() {
                            return ser.serialize_str(s);
                        }
                    }
                }
                ser.collect_seq(self.0.iter().filter_map(|v| v.to_str().ok()))
            } else {
                let mut seq = ser.serialize_seq(Some(count))?;
                for v in self.0.iter() {
                    seq.serialize_element(v.as_bytes())?;
                }
                seq.end()
            }
        }
    }

    /// Implementation detail. Use derive annotations instead.
    pub fn serialize<S: Serializer>(headers: &HeaderMap, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_map(
            headers
                .keys()
                .map(|k| (k.as_str(), ToSeq(headers.get_all(k)))),
        )
    }

    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum OneOrMore<'a> {
        One(Cow<'a, str>),
        Strings(Vec<Cow<'a, str>>),
        Bytes(Vec<Cow<'a, [u8]>>),
    }

    struct HeaderMapVisitor {
        is_human_readable: bool,
    }

    impl<'de> Visitor<'de> for HeaderMapVisitor {
        type Value = HeaderMap;

        // Format a message stating what data this Visitor expects to receive.
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("lots of things can go wrong with HeaderMap")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut map = HeaderMap::with_capacity(access.size_hint().unwrap_or(0));

            if !self.is_human_readable {
                while let Some((key, arr)) = access.next_entry::<Cow<str>, Vec<Cow<[u8]>>>()? {
                    let key = HeaderName::from_bytes(key.as_bytes())
                        .map_err(|_| de::Error::invalid_value(Unexpected::Str(&key), &self))?;
                    for val in arr {
                        let val = HeaderValue::from_bytes(&val).map_err(|_| {
                            de::Error::invalid_value(Unexpected::Bytes(&val), &self)
                        })?;
                        map.append(&key, val);
                    }
                }
            } else {
                while let Some((key, val)) = access.next_entry::<Cow<str>, OneOrMore>()? {
                    let key = HeaderName::from_bytes(key.as_bytes())
                        .map_err(|_| de::Error::invalid_value(Unexpected::Str(&key), &self))?;
                    match val {
                        OneOrMore::One(val) => {
                            let val = val.parse().map_err(|_| {
                                de::Error::invalid_value(Unexpected::Str(&val), &self)
                            })?;
                            map.insert(key, val);
                        }
                        OneOrMore::Strings(arr) => {
                            for val in arr {
                                let val = val.parse().map_err(|_| {
                                    de::Error::invalid_value(Unexpected::Str(&val), &self)
                                })?;
                                map.append(&key, val);
                            }
                        }
                        OneOrMore::Bytes(arr) => {
                            for val in arr {
                                let val = HeaderValue::from_bytes(&val).map_err(|_| {
                                    de::Error::invalid_value(Unexpected::Bytes(&val), &self)
                                })?;
                                map.append(&key, val);
                            }
                        }
                    };
                }
            }
            Ok(map)
        }
    }

    /// Implementation detail.
    pub fn deserialize<'de, D>(de: D) -> Result<HeaderMap, D::Error>
    where
        D: Deserializer<'de>,
    {
        let is_human_readable = de.is_human_readable();
        de.deserialize_map(HeaderMapVisitor { is_human_readable })
    }
}

/// For `http::StatusCode`
///
/// `#[serde(with = "http_serde::status_code")]`
pub mod status_code {
    use http::StatusCode;
    use serde::de;
    use serde::de::{Unexpected, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    /// Implementation detail. Use derive annotations instead.
    pub fn serialize<S: Serializer>(status: &StatusCode, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_u16(status.as_u16())
    }

    struct StatusVisitor;

    impl<'de> Visitor<'de> for StatusVisitor {
        type Value = StatusCode;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "valid status code")
        }

        fn visit_i32<E: de::Error>(self, val: i32) -> Result<Self::Value, E> {
            self.visit_u16(val as u16)
        }

        fn visit_i16<E: de::Error>(self, val: i16) -> Result<Self::Value, E> {
            self.visit_u16(val as u16)
        }

        fn visit_u8<E: de::Error>(self, val: u8) -> Result<Self::Value, E> {
            self.visit_u16(val as u16)
        }

        fn visit_u32<E: de::Error>(self, val: u32) -> Result<Self::Value, E> {
            self.visit_u16(val as u16)
        }

        fn visit_i64<E: de::Error>(self, val: i64) -> Result<Self::Value, E> {
            self.visit_u16(val as u16)
        }

        fn visit_u64<E: de::Error>(self, val: u64) -> Result<Self::Value, E> {
            self.visit_u16(val as u16)
        }

        fn visit_u16<E: de::Error>(self, val: u16) -> Result<Self::Value, E> {
            StatusCode::from_u16(val)
                .map_err(|_| de::Error::invalid_value(Unexpected::Unsigned(val.into()), &self))
        }
    }

    /// Implementation detail.
    pub fn deserialize<'de, D>(de: D) -> Result<StatusCode, D::Error>
    where
        D: Deserializer<'de>,
    {
        de.deserialize_u16(StatusVisitor)
    }
}

/// For `http::Method`
///
/// `#[serde(with = "http_serde::method")]`
pub mod method {
    use http::Method;
    use serde::de;
    use serde::de::{Unexpected, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    /// Implementation detail. Use derive annotations instead.
    pub fn serialize<S: Serializer>(method: &Method, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(method.as_str())
    }

    struct MethodVisitor;

    impl<'de> Visitor<'de> for MethodVisitor {
        type Value = Method;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "valid method name")
        }

        fn visit_str<E: de::Error>(self, val: &str) -> Result<Self::Value, E> {
            val.parse()
                .map_err(|_| de::Error::invalid_value(Unexpected::Str(val), &self))
        }
    }

    /// Implementation detail.
    pub fn deserialize<'de, D>(de: D) -> Result<Method, D::Error>
    where
        D: Deserializer<'de>,
    {
        de.deserialize_str(MethodVisitor)
    }
}

/// For `http::Uri`
///
/// `#[serde(with = "http_serde::uri")]`
pub mod uri {
    use http::Uri;
    use serde::de;
    use serde::de::{Unexpected, Visitor};
    use serde::{Deserializer, Serializer};
    use std::convert::TryInto;
    use std::fmt;

    /// Implementation detail. Use derive annotations instead.
    pub fn serialize<S: Serializer>(uri: &Uri, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(&uri)
    }

    struct UriVisitor;

    impl<'de> Visitor<'de> for UriVisitor {
        type Value = Uri;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "valid uri")
        }

        fn visit_str<E: de::Error>(self, val: &str) -> Result<Self::Value, E> {
            val.parse()
                .map_err(|_| de::Error::invalid_value(Unexpected::Str(val), &self))
        }

        fn visit_string<E: de::Error>(self, val: String) -> Result<Self::Value, E> {
            val.try_into().map_err(de::Error::custom)
        }
    }

    /// Implementation detail.
    pub fn deserialize<'de, D>(de: D) -> Result<Uri, D::Error>
    where
        D: Deserializer<'de>,
    {
        de.deserialize_str(UriVisitor)
    }
}

/// For `http::uri::Authority`
///
/// `#[serde(with = "http_serde::authority")]`
pub mod authority {
    use http::uri::Authority;
    use serde::de;
    use serde::de::{Unexpected, Visitor};
    use serde::{Deserializer, Serializer};
    use std::convert::TryInto;
    use std::fmt;

    /// Implementation detail. Use derive annotations instead.
    pub fn serialize<S: Serializer>(authority: &Authority, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(&authority)
    }

    struct AuthorityVisitor;

    impl<'de> Visitor<'de> for AuthorityVisitor {
        type Value = Authority;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "valid authority")
        }

        fn visit_str<E: de::Error>(self, val: &str) -> Result<Self::Value, E> {
            val.parse()
                .map_err(|_| de::Error::invalid_value(Unexpected::Str(val), &self))
        }

        fn visit_string<E: de::Error>(self, val: String) -> Result<Self::Value, E> {
            val.try_into().map_err(de::Error::custom)
        }
    }

    /// Implementation detail.
    pub fn deserialize<'de, D>(de: D) -> Result<Authority, D::Error>
    where
        D: Deserializer<'de>,
    {
        de.deserialize_str(AuthorityVisitor)
    }
}

/// For `http::Version`
///
/// `#[serde(with = "http_serde::version")]`
pub mod version {
    use http::Version;
    use serde::de::{Unexpected, Visitor};
    use serde::{de, Deserializer, Serializer};
    use std::fmt::Formatter;

    pub fn serialize<S: Serializer>(version: &Version, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(format!("{:?}", version).as_str())
    }

    struct VersionVisitor;

    impl<'de> Visitor<'de> for VersionVisitor {
        type Value = Version;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            write!(formatter, "valid version")
        }

        fn visit_str<E: de::Error>(self, val: &str) -> Result<Self::Value, E> {
            Ok(match val {
                "HTTP/0.9" => Version::HTTP_09,
                "HTTP/1.0" => Version::HTTP_10,
                "HTTP/1.1" => Version::HTTP_11,
                "HTTP/2.0" => Version::HTTP_2,
                "HTTP/3.0" => Version::HTTP_3,
                _ => Err(de::Error::invalid_value(Unexpected::Str(val), &self))?,
            })
        }

        fn visit_string<E: de::Error>(self, val: String) -> Result<Self::Value, E> {
            self.visit_str(val.as_str())
        }
    }

    pub fn deserialize<'de, D>(de: D) -> Result<Version, D::Error>
    where
        D: Deserializer<'de>,
    {
        de.deserialize_str(VersionVisitor)
    }
}
