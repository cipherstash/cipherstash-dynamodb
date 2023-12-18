use super::{Plaintext, PlaintextNullVariant};
use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;

macro_rules! impl_from {
    ($($ty:ty => $variant:ident),*) => {
        $(
            impl From<$ty> for Plaintext {
                fn from(value: $ty) -> Self {
                    Plaintext::$variant(Some(value as _))
                }
            }

            impl From<&$ty> for Plaintext {
                fn from(value: &$ty) -> Self {
                    Plaintext::$variant(Some(value.to_owned() as _))
                }
            }
        )*
    };
}

impl_from! {
    String => Utf8Str,
    bool => Boolean,
    i64 => BigInt,
    i32 => Int,
    i16 => SmallInt,
    f64 => Float,
    Decimal => Decimal,
    NaiveDate => NaiveDate,
    DateTime<Utc> => Timestamp,
    u64 => BigUInt
}

impl From<&str> for Plaintext {
    fn from(value: &str) -> Self {
        Plaintext::Utf8Str(Some(value.to_owned()))
    }
}

impl<T> From<Option<T>> for Plaintext
where
    T: Into<Plaintext> + PlaintextNullVariant,
{
    fn from(value: Option<T>) -> Self {
        if let Some(value) = value {
            value.into()
        } else {
            T::null()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! test_conversion {
        ($name:ident, $ty:ty, $variant:ident, $value:expr) => {
            #[test]
            fn $name() {
                let plaintext: Plaintext = $value.into();
                assert_eq!(plaintext, Plaintext::$variant(Some($value)));

                let plaintext_ref: Plaintext = Plaintext::from(&$value);
                assert_eq!(plaintext_ref, Plaintext::$variant(Some($value.clone())));

                let plaintext_opt_some: Plaintext = Some($value).into();
                assert_eq!(plaintext_opt_some, Plaintext::$variant(Some($value)));

                let plaintext_opt_none: Plaintext = None::<$ty>.into();
                assert_eq!(plaintext_opt_none, Plaintext::$variant(None));
            }
        };
    }

    test_conversion!(
        test_string_conversion,
        String,
        Utf8Str,
        String::from("hello")
    );
    test_conversion!(test_bool_conversion, bool, Boolean, true);
    test_conversion!(test_i64_conversion, i64, BigInt, 1234567890i64);
    test_conversion!(test_i32_conversion, i32, Int, 12345i32);
    test_conversion!(test_i16_conversion, i16, SmallInt, 123i16);
    test_conversion!(test_f64_conversion, f64, Float, 3.14159f64);
    test_conversion!(
        test_decimal_conversion,
        Decimal,
        Decimal,
        Decimal::new(1234, 2)
    );
    test_conversion!(
        test_naive_date_conversion,
        NaiveDate,
        NaiveDate,
        NaiveDate::from_ymd_opt(2021, 8, 31).unwrap()
    );
    test_conversion!(
        test_datetime_conversion,
        DateTime<Utc>,
        Timestamp,
        DateTime::<Utc>::default()
    );
}
