use chrono::{NaiveDate, DateTime, Utc};
use rust_decimal::Decimal;

use super::Plaintext;
use crate::encryption::errors::TypeParseError;

macro_rules! impl_try_from_plaintext {
    ($ty:ty, $variant:ident, $err:expr) => {
        impl TryFrom<Plaintext> for $ty {
            type Error = TypeParseError;

            fn try_from(value: Plaintext) -> Result<Self, Self::Error> {
                match value {
                    Plaintext::$variant(Some(v)) => Ok(v),
                    _ => Err(TypeParseError($err.to_string())),
                }
            }
        }

        impl TryFrom<&Plaintext> for $ty {
            type Error = TypeParseError;

            fn try_from(value: &Plaintext) -> Result<Self, Self::Error> {
                match value {
                    Plaintext::$variant(Some(v)) => Ok(v.clone()),
                    _ => Err(TypeParseError($err.to_string())),
                }
            }
        }
    };
}

impl_try_from_plaintext!(i64, BigInt, "Cannot convert type to i64");
impl_try_from_plaintext!(i32, Int, "Cannot convert type to i32");
impl_try_from_plaintext!(i16, SmallInt, "Cannot convert type to i16");
impl_try_from_plaintext!(f64, Float, "Cannot convert type to f64");
impl_try_from_plaintext!(Decimal, Decimal, "Cannot convert type to Decimal");
impl_try_from_plaintext!(NaiveDate, NaiveDate, "Cannot convert type to NaiveDate");
impl_try_from_plaintext!(DateTime<Utc>, Timestamp, "Cannot convert type to DateTime<Utc>");
impl_try_from_plaintext!(bool, Boolean, "Cannot convert type to bool");
impl_try_from_plaintext!(String, Utf8Str, "Cannot convert type to String");
