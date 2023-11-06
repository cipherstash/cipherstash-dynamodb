use chrono::{NaiveDate, DateTime, Utc};
use rust_decimal::Decimal;
use super::Plaintext;

macro_rules! impl_from {
    ($ty:ty, $variant:ident) => {
        impl From<$ty> for Plaintext {
            fn from(value: $ty) -> Self {
                Plaintext::$variant(Some(value))
            }
        }

        impl From<&$ty> for Plaintext {
            fn from(value: &$ty) -> Self {
                Plaintext::$variant(Some(value.to_owned()))
            }
        }
    };
}

impl_from!(String, Utf8Str);
impl_from!(bool, Boolean);
impl_from!(i64, BigInt);
impl_from!(i32, Int);
impl_from!(i16, SmallInt);
impl_from!(f64, Float);
impl_from!(Decimal, Decimal);
impl_from!(NaiveDate, NaiveDate);
impl_from!(DateTime<Utc>, Timestamp);

impl From<&str> for Plaintext {
    fn from(value: &str) -> Self {
        value.to_string().into()
    }
}

