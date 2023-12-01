use super::{Plaintext, PlaintextNullVariant};
use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;

/// Trait for converting `Self` into `Plaintext`
pub trait ToPlaintext: super::PlaintextNullVariant {
    /// Converts `Self` into `Plaintext`
    fn to_plaintext(self) -> Plaintext;
}

macro_rules! impl_from {
    ($($ty:ty => $variant:ident),*) => {
        $(
            impl ToPlaintext for $ty {
                fn to_plaintext(self) -> Plaintext {
                    Plaintext::$variant(Some(self as _))
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

impl ToPlaintext for &str {
    fn to_plaintext(self) -> Plaintext {
        self.to_owned().to_plaintext()
    }
}

/// Blanket implementation for all references
/// where the referenced type is clonable and implements `ToPlaintext`.
impl<T> ToPlaintext for &T
where
    T: ToPlaintext + Clone,
    for<'r> &'r T: super::PlaintextNullVariant,
{
    fn to_plaintext(self) -> Plaintext {
        self.clone().to_plaintext()
    }
}

/// Blanket implementation for `Option<T>` where
/// `T` implements `ToPlaintext`.
impl<T> ToPlaintext for Option<T>
where
    T: ToPlaintext,
    Option<T>: PlaintextNullVariant,
{
    fn to_plaintext(self) -> Plaintext {
        if let Some(value) = self {
            value.to_plaintext()
        } else {
            Self::null()
        }
    }
}

/// Blanket implementation of `From<T>` for all
/// `T` that implements `ToPlaintext`
impl<T> From<T> for Plaintext
where
    T: ToPlaintext,
{
    fn from(value: T) -> Self {
        value.to_plaintext()
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
