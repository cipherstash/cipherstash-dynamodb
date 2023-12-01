use std::num::TryFromIntError;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;

use super::{Plaintext, PlaintextNullVariant};
use crate::encryption::errors::TypeParseError;

pub trait TryFromPlaintext: Sized {
    fn try_from_plaintext(value: &Plaintext) -> Result<Self, TypeParseError>;
}

macro_rules! impl_try_from_plaintext {
    ($($ty:ty => $variant:ident),*) => {
        $(
            impl TryFromPlaintext for $ty {
                fn try_from_plaintext(value: &Plaintext) -> Result<Self, TypeParseError> {
                    match value {
                        Plaintext::$variant(Some(ref v)) => Ok(v.to_owned().into()),
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

impl<T> TryFromPlaintext for Option<T>
where
    T: TryFromPlaintext + PlaintextNullVariant,
{
    fn try_from_plaintext(value: &Plaintext) -> Result<Self, TypeParseError> {
        match (value, T::null()) {
            // Return OK(None) if the inner value is None
            (Plaintext::BigInt(None), Plaintext::BigInt(_))
            | (Plaintext::BigUInt(None), Plaintext::BigUInt(_))
            | (Plaintext::Boolean(None), Plaintext::Boolean(_))
            | (Plaintext::Decimal(None), Plaintext::Decimal(_))
            | (Plaintext::Float(None), Plaintext::Float(_))
            | (Plaintext::Int(None), Plaintext::Int(_))
            | (Plaintext::NaiveDate(None), Plaintext::NaiveDate(_))
            | (Plaintext::SmallInt(None), Plaintext::SmallInt(_))
            | (Plaintext::Timestamp(None), Plaintext::Timestamp(_))
            | (Plaintext::Utf8Str(None), Plaintext::Utf8Str(_)) => Ok(None),

            // Return Result<Some(T))> if the inner value is Some
            (Plaintext::BigInt(Some(_)), Plaintext::BigInt(_))
            | (Plaintext::BigUInt(Some(_)), Plaintext::BigUInt(_))
            | (Plaintext::Boolean(Some(_)), Plaintext::Boolean(_))
            | (Plaintext::Decimal(Some(_)), Plaintext::Decimal(_))
            | (Plaintext::Float(Some(_)), Plaintext::Float(_))
            | (Plaintext::Int(Some(_)), Plaintext::Int(_))
            | (Plaintext::NaiveDate(Some(_)), Plaintext::NaiveDate(_))
            | (Plaintext::SmallInt(Some(_)), Plaintext::SmallInt(_))
            | (Plaintext::Timestamp(Some(_)), Plaintext::Timestamp(_))
            | (Plaintext::Utf8Str(Some(_)), Plaintext::Utf8Str(_)) => {
                T::try_from_plaintext(value).map(Some)
            }
            // Return type error if the expected variant for T and value doesn't match
            _ => Err(TypeParseError(format!(
                "Cannot convert type to {}",
                std::any::type_name::<Self>()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversion() {
        assert_eq!(
            String::try_from_plaintext(&Plaintext::Utf8Str(Some("Hello".to_string()))).unwrap(),
            "Hello".to_string(),
        );

        assert!(!bool::try_from_plaintext(&Plaintext::Boolean(Some(false))).unwrap());

        assert!(bool::try_from_plaintext(&Plaintext::Boolean(Some(true))).unwrap());

        assert_eq!(
            i64::try_from_plaintext(&Plaintext::BigInt(Some(10))).unwrap(),
            10
        );
        assert_eq!(
            i32::try_from_plaintext(&Plaintext::Int(Some(10))).unwrap(),
            10
        );
        assert_eq!(
            i16::try_from_plaintext(&Plaintext::SmallInt(Some(10))).unwrap(),
            10
        );

        assert_eq!(
            f64::try_from_plaintext(&Plaintext::from(10_f64)).unwrap(),
            10.
        );

        assert_eq!(
            Decimal::try_from_plaintext(&Plaintext::Decimal(Some(Decimal::new(10, 0)))).unwrap(),
            Decimal::new(10, 0),
        );

        assert_eq!(
            NaiveDate::try_from_plaintext(&Plaintext::NaiveDate(Some(
                NaiveDate::from_ymd_opt(2020, 1, 1).expect("Expected date to create")
            )))
            .unwrap(),
            NaiveDate::from_ymd_opt(2020, 1, 1).expect("Expected date to create")
        );

        assert_eq!(
            DateTime::<Utc>::try_from_plaintext(&Plaintext::Timestamp(Some(
                DateTime::<Utc>::from_timestamp(1000, 0).expect("Expected timestamp to create")
            )))
            .unwrap(),
            (DateTime::from_timestamp(1000, 0).expect("Expected timestamp to create")),
        );

        assert_eq!(
            Option::<i64>::try_from_plaintext(&Plaintext::BigInt(Some(42))).unwrap(),
            Some(42)
        );

        assert_eq!(
            Option::<i64>::try_from_plaintext(&Plaintext::BigInt(None)).unwrap(),
            None,
        );
    }
}
