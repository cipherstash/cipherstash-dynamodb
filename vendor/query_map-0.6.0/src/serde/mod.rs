//!
//! The serde module implements derializers for payloads into QueryMap.
//! You need to enable the feature `serde` to access these deserializers.
//!

/// The aws_api_gateway_v2 module implements a deserializer that works with
/// the expected format in the AWS Api Gateway V2 payloads.
/// See https://github.com/calavera/query-map-rs/issues/1#issuecomment-1114463009 for more detail.
pub mod aws_api_gateway_v2;

/// The standard module implements a deserializer that follows the URL encoding parser standard.
/// See https://url.spec.whatwg.org/#urlencoded-parsing for more detail.
pub mod standard;
