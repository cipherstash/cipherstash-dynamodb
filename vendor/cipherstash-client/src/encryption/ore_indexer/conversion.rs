use crate::encryption::plaintext::Plaintext;
use chrono::Datelike;
use ore_rs::{CipherText, OreCipher, OreEncrypt, OreError};

// TODO: Would be good to implement as Into and TryInto<OrePlaintext>
// This implies also that the scheme is either generic on its plaintext type or it is fixed (e.g. u64)
pub trait IntoOrePlaintext<T: PartialEq + PartialOrd> {
    fn to_ore(&self) -> OrePlaintext<T>;
}

// This type will be moved into ore.rs at some point
#[derive(Debug, PartialEq, PartialOrd)]
pub struct OrePlaintext<T: PartialEq + PartialOrd>(T);

impl OrePlaintext<u64> {
    // Commenting out for now, we'll need this soon
    //pub fn encrypt_left<T: OreCipher>(&self, cipher: &T) -> Result<Left<T, 8>, OreError> {
    //    self.0.encrypt_left(cipher)
    //}

    pub fn encrypt<T: OreCipher>(&self, cipher: &T) -> Result<CipherText<T, 8>, OreError> {
        self.0.encrypt(cipher)
    }
}

impl IntoOrePlaintext<u64> for i16 {
    fn to_ore(&self) -> OrePlaintext<u64> {
        let r = *self as u16 ^ (u16::MAX / 2 + 1);
        OrePlaintext(r.into())
    }
}

impl IntoOrePlaintext<u64> for i32 {
    fn to_ore(&self) -> OrePlaintext<u64> {
        let r = *self as u32 ^ (u32::MAX / 2 + 1);
        OrePlaintext(r.into())
    }
}

impl IntoOrePlaintext<u64> for i64 {
    fn to_ore(&self) -> OrePlaintext<u64> {
        OrePlaintext(*self as u64 ^ (u64::MAX / 2 + 1))
    }
}

impl IntoOrePlaintext<u64> for f64 {
    fn to_ore(&self) -> OrePlaintext<u64> {
        // Taken from ore_encoding
        let mut value = *self;

        if value == -0.0f64 {
            value = 0.0f64;
        }
        use core::mem::transmute;
        let num: u64 = value.to_bits();
        let signed: i64 = -(unsafe { transmute(num >> 63) });
        let mut mask: u64 = unsafe { transmute(signed) };
        mask |= 0x8000000000000000;
        OrePlaintext(num ^ mask)
    }
}

impl IntoOrePlaintext<u64> for &Plaintext {
    fn to_ore(&self) -> OrePlaintext<u64> {
        match self {
            Plaintext::BigInt(Some(x)) => x.to_ore(),
            // TODO: Bools should get special handling with a small domain ORE
            // Or a non-deterministic hash - btrees don't really make sense tbh
            Plaintext::Boolean(Some(x)) => OrePlaintext(*x as u64),
            Plaintext::Decimal(_) => unimplemented!("Decimals not yet supported by ORE"),
            Plaintext::Float(Some(x)) => x.to_ore(),
            Plaintext::Int(Some(x)) => x.to_ore(),
            Plaintext::NaiveDate(Some(x)) => x.num_days_from_ce().to_ore(),
            Plaintext::SmallInt(Some(x)) => x.to_ore(),
            // Timestamp as ORE depends on the range of possible values
            Plaintext::Timestamp(_) => unimplemented!("Timestamp not yet supported by ORE"),
            // TODO: Use orderise string
            // Ideally, ore.rs should have a "bytes" plaintext type
            Plaintext::Utf8Str(_) => unimplemented!(),
            // TODO: Move orderise string (and bloom filter) into this crate
            // and remove the cipherstash-core and protect deps
            _ => unimplemented!("Null values not supported by ORE"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::plaintext::Plaintext;
    use chrono::NaiveDate;

    #[test]
    fn test_i64_preserve_ordering() {
        assert!((-1i64).to_ore() < 100i64.to_ore());
        assert!((10i64).to_ore() < 100i64.to_ore());
        assert!((i64::MIN).to_ore() < i64::MAX.to_ore());
        assert_eq!((0i64).to_ore(), 0i64.to_ore());
    }

    #[test]
    fn test_naive_date_preserves_ordering() {
        assert!(
            (&Plaintext::NaiveDate(Some(NaiveDate::from_ymd_opt(2023, 2, 3).unwrap()))).to_ore()
                < (&Plaintext::NaiveDate(Some(NaiveDate::from_ymd_opt(2023, 2, 4).unwrap())))
                    .to_ore()
        );
        assert!(
            (&Plaintext::NaiveDate(Some(NaiveDate::from_ymd_opt(2024, 2, 3).unwrap()))).to_ore()
                > (&Plaintext::NaiveDate(Some(NaiveDate::from_ymd_opt(2023, 2, 4).unwrap())))
                    .to_ore()
        );
        assert_eq!(
            (&Plaintext::NaiveDate(Some(NaiveDate::from_ymd_opt(2024, 5, 5).unwrap()))).to_ore(),
            (&Plaintext::NaiveDate(Some(NaiveDate::from_ymd_opt(2024, 5, 5).unwrap()))).to_ore()
        );
    }
}
