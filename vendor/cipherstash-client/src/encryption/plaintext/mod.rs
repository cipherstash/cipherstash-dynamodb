use super::errors::TypeParseError;
use chrono::{DateTime, Datelike, NaiveDate, TimeZone, Utc};
use rust_decimal::Decimal;
use schema::ColumnType;
use zeroize::Zeroize;

mod from_conversion;
mod to_conversion;

const VERSION: u8 = 1;

const BIGINT_TYPE: u8 = 1;
const BOOLEAN_TYPE: u8 = 2;
const DECIMAL_TYPE: u8 = 3;
const FLOAT_TYPE: u8 = 4;
const INT_TYPE: u8 = 5;
const SMALLINT_TYPE: u8 = 6;
const TIMESTAMP_TYPE: u8 = 7;
const UTF8STR_TYPE: u8 = 8;
const NAIVE_DATE_TYPE: u8 = 9;
const BIGUINT_TYPE: u8 = 10;

const NULL_FLAGS_MASK: u8 = 0b10000000;
const VARIANT_FLAGS_MASK: u8 = NULL_FLAGS_MASK ^ 0b11111111;

// TODO: Implement Zeroize for Plaintext
#[derive(Debug, PartialEq, Clone)]
pub enum Plaintext {
    BigInt(Option<i64>),
    BigUInt(Option<u64>),
    Boolean(Option<bool>),
    Decimal(Option<Decimal>),
    Float(Option<f64>),
    Int(Option<i32>),
    NaiveDate(Option<NaiveDate>),
    SmallInt(Option<i16>),
    Timestamp(Option<DateTime<Utc>>),
    Utf8Str(Option<String>),
}

/// Lifted directly from the `zeroize` crate.
///
/// This method is used to make sure the compiler will correctly order operations so that
/// non-zeroes don't get read when something is being zeroized.
#[inline(always)]
fn atomic_fence() {
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

impl Zeroize for Plaintext {
    fn zeroize(&mut self) {
        match self {
            Self::Timestamp(x) => unsafe {
                // DatTime<Utc> is completely stack allocated so safe to just write zeroes
                std::ptr::write_volatile(x, std::mem::zeroed());
                std::ptr::write_volatile(x, None);
                atomic_fence();
            },

            Self::NaiveDate(x) => unsafe {
                // NaiveDate is completely stack allocated so safe to just write zeroes
                std::ptr::write_volatile(x, std::mem::zeroed());
                std::ptr::write_volatile(x, None);
                atomic_fence();
            },

            Self::Decimal(x) => unsafe {
                // Decimal is completely stack allocated so safe to just write zeroes
                std::ptr::write_volatile(x, std::mem::zeroed());
                std::ptr::write_volatile(x, None);
                atomic_fence();
            },

            // The following have existing zeroize impls
            Self::BigInt(x) => x.zeroize(),
            Self::BigUInt(x) => x.zeroize(),
            Self::Boolean(x) => x.zeroize(),
            Self::Float(x) => x.zeroize(),
            Self::Int(x) => x.zeroize(),
            Self::SmallInt(x) => x.zeroize(),
            Self::Utf8Str(x) => x.zeroize(),
        }
    }
}

impl Drop for Plaintext {
    // ZeroizeOnDrop only works when all branches implement Zeroize.
    // Since we manually implement Zeroize it's easier to just zerize on drop manually.
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Plaintext {
    pub fn null_for_column_type(column_type: &ColumnType) -> Self {
        match column_type {
            ColumnType::BigInt => Self::BigInt(None),
            ColumnType::Boolean => Self::Boolean(None),
            ColumnType::Date => Self::NaiveDate(None),
            ColumnType::Decimal => Self::Decimal(None),
            ColumnType::Float => Self::Float(None),
            ColumnType::Int => Self::Int(None),
            ColumnType::SmallInt => Self::SmallInt(None),
            ColumnType::Timestamp => Self::Timestamp(None),
            ColumnType::Utf8Str => Self::Utf8Str(None),
        }
    }

    /// Version s the first byte
    /// The type variant is the 2nd byte
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out: Vec<u8> = vec![VERSION, self.flags()];
        // Append
        match self {
            Self::BigInt(Some(value)) => out.append(&mut value.to_be_bytes().to_vec()),
            Self::BigUInt(Some(value)) => out.append(&mut value.to_be_bytes().to_vec()),
            Self::Boolean(Some(value)) => out.push(u8::from(*value)),
            Self::Decimal(Some(value)) => out.append(&mut value.serialize().to_vec()),
            Self::Float(Some(value)) => out.append(&mut value.to_be_bytes().to_vec()),
            Self::Int(Some(value)) => out.append(&mut value.to_be_bytes().to_vec()),
            Self::NaiveDate(Some(value)) => {
                out.append(&mut value.num_days_from_ce().to_be_bytes().to_vec())
            }
            Self::SmallInt(Some(value)) => out.append(&mut value.to_be_bytes().to_vec()),
            Self::Timestamp(Some(value)) => {
                out.append(&mut value.timestamp_millis().to_be_bytes().to_vec())
            }
            Self::Utf8Str(Some(value)) => out.append(&mut value.as_bytes().to_vec()),
            _ => {}
        }

        out
    }

    pub fn from_slice(data: &[u8]) -> Result<Self, TypeParseError> {
        // Don't care about version right now
        let _version = data.first().ok_or(TypeParseError(
            "Invalid byte array: missing version".to_string(),
        ))?;
        let flags = *data.get(1).ok_or(TypeParseError(
            "Invalid byte array: missing flags".to_string(),
        ))?;

        let is_null: bool = flags & NULL_FLAGS_MASK == NULL_FLAGS_MASK;
        let variant: u8 = flags & VARIANT_FLAGS_MASK;
        let bytes = &data[2..];

        match is_null {
            true => match variant {
                BIGINT_TYPE => Ok(Self::BigInt(None)),
                BOOLEAN_TYPE => Ok(Self::Boolean(None)),
                DECIMAL_TYPE => Ok(Self::Decimal(None)),
                FLOAT_TYPE => Ok(Self::Float(None)),
                INT_TYPE => Ok(Self::Int(None)),
                NAIVE_DATE_TYPE => Ok(Self::NaiveDate(None)),
                SMALLINT_TYPE => Ok(Self::SmallInt(None)),
                TIMESTAMP_TYPE => Ok(Self::Timestamp(None)),
                UTF8STR_TYPE => Ok(Self::Utf8Str(None)),
                _ => Err(TypeParseError(format!("Unknown variant code `{variant}`"))),
            },
            false => match variant {
                BIGINT_TYPE => {
                    let val = i64::from_be_bytes(
                        bytes
                            .try_into()
                            .map_err(|_| TypeParseError::make(bytes, variant))?,
                    );
                    Ok(Self::BigInt(Some(val)))
                }
                BOOLEAN_TYPE => {
                    if bytes.len() != 1 || bytes[0] > 1 {
                        return Err(TypeParseError::make(bytes, variant));
                    }
                    Ok(Self::Boolean(Some(bytes[0] == 1)))
                }
                DECIMAL_TYPE => Ok(Self::Decimal(Some(Decimal::deserialize(
                    bytes
                        .try_into()
                        .map_err(|_| TypeParseError::make(bytes, variant))?,
                )))),
                FLOAT_TYPE => Ok(Self::Float(Some(f64::from_be_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| TypeParseError::make(bytes, variant))?,
                )))),
                INT_TYPE => Ok(Self::Int(Some(i32::from_be_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| TypeParseError::make(bytes, variant))?,
                )))),
                NAIVE_DATE_TYPE => Ok(Self::NaiveDate(Some(
                    NaiveDate::from_num_days_from_ce_opt(i32::from_be_bytes(
                        bytes
                            .try_into()
                            .map_err(|_| TypeParseError::make(bytes, variant))?,
                    ))
                    .ok_or(TypeParseError::make(bytes, variant))?,
                ))),
                SMALLINT_TYPE => Ok(Self::SmallInt(Some(i16::from_be_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| TypeParseError::make(bytes, variant))?,
                )))),
                TIMESTAMP_TYPE => Ok(Self::Timestamp(Some(
                    Utc.timestamp_millis_opt(i64::from_be_bytes(
                        bytes
                            .try_into()
                            .map_err(|_| TypeParseError::make(bytes, variant))?,
                    ))
                    .single()
                    .ok_or(TypeParseError::make(bytes, variant))?,
                ))),
                UTF8STR_TYPE => Ok(Self::Utf8Str(Some(
                    String::from_utf8_lossy(bytes).to_string(),
                ))),
                _ => Err(TypeParseError(format!("Unknown variant code `{variant}`"))),
            },
        }
    }

    pub fn flags(&self) -> u8 {
        match self {
            Self::BigInt(Some(_)) => BIGINT_TYPE,
            Self::BigUInt(Some(_)) => BIGUINT_TYPE,
            Self::Boolean(Some(_)) => BOOLEAN_TYPE,
            Self::Decimal(Some(_)) => DECIMAL_TYPE,
            Self::Float(Some(_)) => FLOAT_TYPE,
            Self::Int(Some(_)) => INT_TYPE,
            Self::NaiveDate(Some(_)) => NAIVE_DATE_TYPE,
            Self::SmallInt(Some(_)) => SMALLINT_TYPE,
            Self::Timestamp(Some(_)) => TIMESTAMP_TYPE,
            Self::Utf8Str(Some(_)) => UTF8STR_TYPE,

            Self::BigInt(None) => NULL_FLAGS_MASK | BIGINT_TYPE,
            Self::BigUInt(None) => NULL_FLAGS_MASK | BIGUINT_TYPE,
            Self::Boolean(None) => NULL_FLAGS_MASK | BOOLEAN_TYPE,
            Self::Decimal(None) => NULL_FLAGS_MASK | DECIMAL_TYPE,
            Self::Float(None) => NULL_FLAGS_MASK | FLOAT_TYPE,
            Self::Int(None) => NULL_FLAGS_MASK | INT_TYPE,
            Self::NaiveDate(None) => NULL_FLAGS_MASK | NAIVE_DATE_TYPE,
            Self::SmallInt(None) => NULL_FLAGS_MASK | SMALLINT_TYPE,
            Self::Timestamp(None) => NULL_FLAGS_MASK | TIMESTAMP_TYPE,
            Self::Utf8Str(None) => NULL_FLAGS_MASK | UTF8STR_TYPE,
        }
    }

    pub fn is_null(&self) -> bool {
        self.flags() & NULL_FLAGS_MASK == NULL_FLAGS_MASK
    }

    pub fn variant_name(variant: u8) -> &'static str {
        let variant: u8 = variant & VARIANT_FLAGS_MASK;

        match variant {
            BIGINT_TYPE => "bigint",
            BOOLEAN_TYPE => "boolean",
            DECIMAL_TYPE => "decimal",
            FLOAT_TYPE => "float",
            INT_TYPE => "int",
            NAIVE_DATE_TYPE => "naivedate",
            SMALLINT_TYPE => "smallint",
            TIMESTAMP_TYPE => "timestamp",
            UTF8STR_TYPE => "utf8str",
            _ => "unknown",
        }
    }

    pub fn to_inner<T: TryFrom<Plaintext>>(self) -> Result<T, T::Error> {
        T::try_from(self)
    }

    pub fn to_inner_from_ref<T: TryFrom<Plaintext>>(&self) -> Result<T, T::Error> {
        self.clone().to_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;
    use std::f64::consts::PI;

    // TODO: These tests could be property tests

    #[test]
    fn test_round_trip_bigint() -> Result<(), Box<dyn std::error::Error>> {
        let result = Plaintext::from_slice(&Plaintext::BigInt(Some(1234567)).to_vec())?;
        assert!(matches!(result, Plaintext::BigInt(Some(1234567))));

        Ok(())
    }

    #[test]
    fn test_round_trip_boolean() -> Result<(), Box<dyn std::error::Error>> {
        let result = Plaintext::from_slice(&Plaintext::Boolean(Some(true)).to_vec())?;
        assert!(matches!(result, Plaintext::Boolean(Some(true))));
        let result = Plaintext::from_slice(&Plaintext::Boolean(Some(false)).to_vec())?;
        assert!(matches!(result, Plaintext::Boolean(Some(false))));

        Ok(())
    }

    #[test]
    fn test_round_trip_decimal() -> Result<(), Box<dyn std::error::Error>> {
        let result =
            Plaintext::from_slice(&Plaintext::Decimal(Some(dec!(999888777.123))).to_vec())?;
        assert!(matches!(result, Plaintext::Decimal(val) if val == Some(dec!(999888777.123))));

        Ok(())
    }

    #[test]
    fn test_round_trip_float() -> Result<(), Box<dyn std::error::Error>> {
        let result = Plaintext::from_slice(&Plaintext::Float(Some(PI)).to_vec())?;
        assert!(matches!(result, Plaintext::Float(v) if v == Some(PI)));

        Ok(())
    }

    #[test]
    fn test_round_trip_int() -> Result<(), Box<dyn std::error::Error>> {
        let result = Plaintext::from_slice(&Plaintext::Int(Some(-34567)).to_vec())?;
        assert!(matches!(result, Plaintext::Int(Some(-34567))));

        Ok(())
    }

    #[test]
    fn test_round_trip_naive_date() -> Result<(), Box<dyn std::error::Error>> {
        let date = NaiveDate::from_ymd_opt(2023, 2, 3).unwrap();
        let result = Plaintext::from_slice(&Plaintext::NaiveDate(Some(date)).to_vec())?;
        assert!(matches!(result, Plaintext::NaiveDate(val) if val == Some(date)));

        Ok(())
    }

    #[test]
    fn test_round_trip_smallint() -> Result<(), Box<dyn std::error::Error>> {
        let result = Plaintext::from_slice(&Plaintext::SmallInt(Some(299)).to_vec())?;
        assert!(matches!(result, Plaintext::SmallInt(Some(299))));

        Ok(())
    }

    #[test]
    fn test_round_trip_timestamp() -> Result<(), Box<dyn std::error::Error>> {
        let ts: DateTime<Utc> = "2021-05-12 15:30:10Z".parse().expect("Timestamp to parse");
        let result = Plaintext::from_slice(&Plaintext::Timestamp(Some(ts)).to_vec())?;
        assert!(matches!(result, Plaintext::Timestamp(val) if val == Some(ts)));

        Ok(())
    }

    #[test]
    fn test_round_trip_utf8str() -> Result<(), Box<dyn std::error::Error>> {
        let result =
            Plaintext::from_slice(&Plaintext::Utf8Str(Some("John Doe".to_string())).to_vec())?;
        assert!(
            matches!(result, Plaintext::Utf8Str(ref val) if val == &Some("John Doe".to_string()))
        );

        Ok(())
    }

    #[test]
    fn test_zeroize_should_not_panic() {
        let mut x = Plaintext::from(false);
        x.zeroize();
        assert_eq!(x, Plaintext::Boolean(None));

        let mut x = Plaintext::from(10_i16);
        x.zeroize();
        assert_eq!(x, Plaintext::SmallInt(None));

        let mut x = Plaintext::from(10_i32);
        x.zeroize();
        assert_eq!(x, Plaintext::Int(None));

        let mut x = Plaintext::from(10_i64);
        x.zeroize();
        assert_eq!(x, Plaintext::BigInt(None));

        let mut x = Plaintext::from(10_f64);
        x.zeroize();
        assert_eq!(x, Plaintext::Float(None));

        let mut x = Plaintext::from(DateTime::<Utc>::MAX_UTC);
        x.zeroize();
        assert_eq!(x, Plaintext::Timestamp(None));

        let mut x = Plaintext::from(NaiveDate::MAX);
        x.zeroize();
        assert_eq!(x, Plaintext::NaiveDate(None));

        let mut x = Plaintext::from("Hello!");
        x.zeroize();
        assert_eq!(x, Plaintext::Utf8Str(None));
    }
}
