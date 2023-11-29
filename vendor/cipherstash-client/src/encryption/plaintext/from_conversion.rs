use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;

use super::Plaintext;
use crate::encryption::errors::TypeParseError;

macro_rules! impl_try_from_plaintext {
    ($($ty:ty => $variant:ident),*) => {
        $(
            impl TryFrom<Plaintext> for $ty {
                type Error = TypeParseError;

                fn try_from(value: Plaintext) -> Result<Self, Self::Error> {
                    match value {
                        Plaintext::$variant(Some(ref v)) => Ok(v.to_owned().into()),
                        _ => Err(TypeParseError(concat!("Cannot convert type to ", stringify!($ty)).to_string())),
                    }
                }
            }

            impl TryFrom<Plaintext> for Option<$ty> {
                type Error = TypeParseError;

                fn try_from(value: Plaintext) -> Result<Self, Self::Error> {
                    match value {
                        Plaintext::$variant(ref x) => Ok(x.clone().into()),
                        _ => Err(TypeParseError(concat!("Cannot convert type to ", stringify!($ty)).to_string())),
                    }
                }
            }
        )*
    };
}

impl_try_from_plaintext! {
    i64 => BigInt,
    i32 => Int,
    i16 => SmallInt,

    u64 => BigUInt,

    f64 => Float,
    Decimal => Decimal,
    NaiveDate => NaiveDate,
    DateTime<Utc> => Timestamp,
    bool => Boolean,
    String => Utf8Str
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversion() {
        assert_eq!(
            String::try_from(Plaintext::Utf8Str(Some("Hello".to_string()))).unwrap(),
            "Hello".to_string(),
        );

        assert!(!bool::try_from(Plaintext::Boolean(Some(false))).unwrap());

        assert!(bool::try_from(Plaintext::Boolean(Some(true))).unwrap());

        assert_eq!(i64::try_from(Plaintext::BigInt(Some(10))).unwrap(), 10);
        assert_eq!(i32::try_from(Plaintext::Int(Some(10))).unwrap(), 10);
        assert_eq!(i16::try_from(Plaintext::SmallInt(Some(10))).unwrap(), 10);

        assert_eq!(f64::try_from(Plaintext::from(10_f64)).unwrap(), 10.);

        assert_eq!(
            Decimal::try_from(Plaintext::Decimal(Some(Decimal::new(10, 0)))).unwrap(),
            Decimal::new(10, 0),
        );

        assert_eq!(
            NaiveDate::try_from(Plaintext::NaiveDate(Some(
                NaiveDate::from_ymd_opt(2020, 1, 1).expect("Expected date to create")
            )))
            .unwrap(),
            NaiveDate::from_ymd_opt(2020, 1, 1).expect("Expected date to create")
        );

        assert_eq!(
            DateTime::<Utc>::try_from(Plaintext::Timestamp(Some(
                DateTime::<Utc>::from_timestamp(1000, 0).expect("Expected timestamp to create")
            )))
            .unwrap(),
            (DateTime::from_timestamp(1000, 0).expect("Expected timestamp to create")),
        );
    }
}
