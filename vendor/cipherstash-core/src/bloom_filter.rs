use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashSet;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum CreateBloomFilterError {
    #[error("InvalidFilterSize: {0}")]
    InvalidFilterSize(String),
    #[error("InvalidFilterTermBits: {0}")]
    InvalidFilterTermBits(String),
}

pub type FilterKey = [u8; 32];

/// A bloom filter implementation designed to be used with the *FilterMatch index types.
#[derive(Debug)]
pub struct BloomFilter {
    /// The key used by the filter's hashing function
    key: FilterKey,

    /// The "set" of bits of the bloom filter
    bits: HashSet<u16>,

    /// The number of hash functions applied to each term. Same as "filterTermBits" in the schema mapping and public docs.
    ///
    /// Implemented as k slices of a single hash.
    ///
    /// Valid values are integers from 3 to 16.
    k: usize,

    /// The size of the bloom filter in bits. Same as "filterSize" in the schema mapping and public docs.
    ///
    /// Since we only keep track of the set bits, the filter size determines the maximum value of the positions stored in the bits attr.
    /// Bit positions are zero-indexed and will have values >= 0 and <= m-1.
    ///
    /// Valid values are powers of 2 from 32 to 65536.
    m: u32,
}

#[derive(Default, Clone, Copy)]
pub struct BloomFilterOps {
    /// The size of the filter in bits (often referred to as `m`)
    pub filter_size: Option<u32>,

    /// The number of hash functions (often referred to as `k`)
    pub hash_function_count: Option<usize>,
}

impl BloomFilterOps {
    pub fn with_filter_size(mut self, size: u32) -> Self {
        self.filter_size = Some(size);
        self
    }

    pub fn with_hash_function_count(mut self, bits: usize) -> Self {
        self.hash_function_count = Some(bits);
        self
    }
}

impl BloomFilter {
    pub const K_MIN: usize = 3;
    pub const K_MAX: usize = 16;
    pub const K_DEFAULT: usize = 3;

    pub const M_MIN: u32 = 32;
    pub const M_MAX: u32 = 65536;
    pub const M_DEFAULT: u32 = 256;

    /// Create a [`BloomFilterOps`] struct used to pass options to the bloom filter.
    pub fn opts() -> BloomFilterOps {
        BloomFilterOps::default()
    }

    /// Create a new [`BloomFilter`] from a given key and filter match index settings.
    ///
    /// ## Example
    ///
    /// Create a bloom filter with custom options.
    ///
    /// ```
    /// # use cipherstash_core::bloom_filter::BloomFilter;
    /// # fn get_key() -> [ u8; 32 ] { [ 1; 32 ] }
    /// #
    /// let filter = BloomFilter::new(
    ///   get_key(),
    ///   BloomFilter::opts()
    ///     .with_filter_size(256)
    ///     .with_hash_function_count(3)
    /// ).expect("Expected filter to create");
    /// ```
    pub fn new(key: FilterKey, opts: BloomFilterOps) -> Result<Self, CreateBloomFilterError> {
        let k = opts.hash_function_count.unwrap_or(Self::K_DEFAULT);
        Self::validate_filter_term_bits(k)?;

        let m = opts.filter_size.unwrap_or(Self::M_DEFAULT);
        Self::validate_filter_size(m)?;

        Ok(Self {
            key,
            bits: Default::default(),
            k,
            m,
        })
    }

    /// Validate that the given `filter_term_bits` is a valid `k` value for this bloom filter.
    fn validate_filter_term_bits(k: usize) -> Result<(), CreateBloomFilterError> {
        if !(Self::K_MIN..=Self::K_MAX).contains(&k) {
            return Err(CreateBloomFilterError::InvalidFilterTermBits(format!(
                "Expected filter_term_bits to be between {} and {}. Got: {}",
                Self::K_MIN,
                Self::K_MAX,
                k
            )));
        }

        Ok(())
    }

    /// Validate that the given `filter_size` is a valid `m` value for this bloom filter.
    fn validate_filter_size(m: u32) -> Result<(), CreateBloomFilterError> {
        if !(Self::M_MIN..=Self::M_MAX).contains(&m) {
            return Err(CreateBloomFilterError::InvalidFilterSize(format!(
                "Expected filter_size to be between {} and {}. Got: {}",
                Self::M_MIN,
                Self::M_MAX,
                m
            )));
        }

        if !m.is_power_of_two() {
            return Err(CreateBloomFilterError::InvalidFilterSize(format!(
                "Expected filter_size to be a power of two. Got: {m}"
            )));
        }

        Ok(())
    }

    pub fn with_terms<T: AsRef<str>>(mut self, terms: impl IntoIterator<Item = T>) -> Self {
        self.add_terms(terms);
        self
    }

    pub fn add_terms<T: AsRef<str>>(&mut self, terms: impl IntoIterator<Item = T>) {
        for term in terms.into_iter() {
            self.add_single_term(term);
        }
    }

    pub fn add_single_term(&mut self, term: impl AsRef<str>) {
        let mut mac: Hmac<Sha256> =
            Hmac::new_from_slice(&self.key).expect("Expected Hmac to create from any size key");
        mac.update(term.as_ref().as_bytes());

        let hash = mac.finalize().into_bytes();

        for index in 0..self.k {
            let slice = &hash[(index * 2)..=(index * 2) + 1];

            let bytes: [u8; 2] = slice
                .try_into()
                // Unless the implementation is wrong this will always return 2 bytes.
                .expect("Expected hash slice to be two bytes");

            // Since the max value for self.m is u16::MAX_VALUE + 1 the output of `% self.m`
            // will always fit into a u16.
            let byte_position = ((u16::from_le_bytes(bytes) as u32) % self.m) as u16;

            self.bits.insert(byte_position);
        }
    }

    /// Check whether this bloom filter is a subset of another.
    pub fn is_subset(&self, other: &Self) -> bool {
        self.bits.is_subset(&other.bits)
    }

    /// Convert the bloom filter into an array of "bits"
    pub fn into_vec(self) -> Vec<u16> {
        self.bits.into_iter().collect()
    }

    /// Create a bloom filter from a key.
    ///
    /// Since this method creates a bloom filter with default options it is guaranteed to succeed.
    pub fn from_key(key: FilterKey) -> Self {
        Self::new(key, Default::default())
            .expect("Expected filter with default options to create without error")
    }

    /// Check whether the bloom filter contains no elements
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;

    use super::*;
    use hex_literal::hex;
    use rand::{distributions::Alphanumeric, Rng}; // 0.8

    fn test_key() -> [u8; 32] {
        hex!("b6d6dba3be33ffaabb83af611ec043b9270dacdc7b3015ce2c36ba17cf2d3b2c")
    }

    fn random_chars(count: usize) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(count)
            .map(char::from)
            .collect()
    }

    fn create_test_filter() -> BloomFilter {
        BloomFilter::from_key(test_key())
    }

    #[test]
    fn test_filter_creates_without_error() {
        let mut filter = BloomFilter::from_key([1; 32]);
        filter.add_terms(["yo"]);
    }

    #[test]
    fn test_add_terms_with_multiple_types() {
        let mut filter = BloomFilter::from_key([1; 32]);

        filter.add_terms(["yo"]);
        filter.add_terms(vec!["yo"]);
        filter.add_terms(vec![String::from("yo")]);
        filter.add_terms([Cow::<'_, str>::from("asdf")]);
    }

    #[test]
    fn test_creates_with_empty_bits() {
        let filter = BloomFilter::from_key(test_key());
        assert!(filter.bits.is_empty())
    }

    #[test]
    fn test_provide_default_for_m() {
        let filter = BloomFilter::from_key(test_key());
        assert_eq!(filter.m, 256);
    }

    #[test]
    fn test_provide_default_for_k() {
        let filter = BloomFilter::from_key(test_key());
        assert_eq!(filter.k, 3);
    }

    macro_rules! bloom_filter_tests {
        (valid_m_values => ($($m: tt),*), valid_k_values => ($($k: tt),*), invalid_m_values => ($($invalid_m: tt),*)) => {
            // Test cases using known valid m values
            $(
                paste::paste! {
                    #[test]
                    fn [<test_m_value_ $m _is_valid>]() {
                        BloomFilter::new(
                            test_key(),
                            BloomFilter::opts().with_filter_size($m)
                        )
                            .expect("Expected filter to create successfully");
                    }

                    #[test]
                    fn [<test_add_bit_positions_with_values_gt_0_and_lt $m _when_m_is_ $m>]() {
                        let mut filter = BloomFilter::new(
                            test_key(),
                            BloomFilter::opts()
                                .with_filter_size($m)
                        ).unwrap();

                        let chars = random_chars(3);

                        println!("Inserting chars: {}", chars);

                        filter.add_single_term(chars);

                        assert_eq!(filter.m, $m);
                        assert!(filter.bits.len() > 0);
                        assert!(filter.bits.iter().all(|b| (*b as u32) < $m));
                    }
                }
            )*

            // Test cases using known valid k values
            $(
                paste::paste! {
                    #[test]
                    fn [<test_k_value_ $k _is_valid>]() {
                        BloomFilter::new(
                            test_key(),
                            BloomFilter::opts().with_hash_function_count($k)
                        )
                            .expect("Expected filter to create successfully");
                    }

                    #[test]
                    fn [<test_adds_at_most_ $k _entries_to_bits_for_a_single_term_when_k_is_ $k>]() {
                        let mut filter = BloomFilter::new(
                            test_key(),
                            BloomFilter::opts()
                                .with_hash_function_count($k)
                        ).unwrap();

                        let chars = random_chars(3);

                        println!("Inserting chars: {}", chars);

                        filter.add_single_term(chars);

                        assert_eq!(filter.k, $k);
                        assert!(filter.bits.len() > 0);
                        assert!(filter.bits.len() <= $k);
                    }
                }
            )*

            // Test cases for attempting to construct a filter with an invalid m value
            $(
                paste::paste! {
                    #[test]
                    fn [<test_m_value $invalid_m _is_not_valid>]() {
                        let err = BloomFilter::new(
                            test_key(),
                            BloomFilter::opts()
                                .with_filter_size($invalid_m)
                        ).expect_err("Expected value to panic");

                        assert!(matches!(err, CreateBloomFilterError::InvalidFilterSize(_)));
                    }
                }
            )*

            // Generate all the k + m permutation tests to check that it works with random strings
            bloom_filter_tests!(@perms ($($m,)*) ($($k,)*));
        };

        // Test cases for testing all permutations of valid k and m values
        (@perms ($m:tt, $($m_tail:tt,)*) ($($k: tt,)*)) => {
            $(
                paste::paste! {
                    #[test]
                    fn [<test_filter_works_with_m_value_ $m _and_k_value $k >]() {
                        let mut filter_a = BloomFilter::new(
                            test_key(),
                            BloomFilter::opts()
                                .with_filter_size($m)
                                .with_hash_function_count($k),
                        )
                        .unwrap();

                        let mut filter_b = BloomFilter::new(
                            test_key(),
                            BloomFilter::opts()
                                .with_filter_size($m)
                                .with_hash_function_count($k),
                        )
                        .unwrap();

                        let mut filter_c = BloomFilter::new(
                            test_key(),
                            BloomFilter::opts()
                                .with_filter_size($m)
                                .with_hash_function_count($k),
                        )
                        .unwrap();

                        let mut filter_d = BloomFilter::new(
                            test_key(),
                            BloomFilter::opts()
                                .with_filter_size($m)
                                .with_hash_function_count($k),
                        )
                        .unwrap();

                        filter_a.add_terms([ "a", "b", "c" ]);

                        // Subset of filter a
                        filter_b.add_terms([ "a", "b" ]);

                        // Zero subset intersection with filter_a
                        filter_c.add_terms([ "d", "e" ]);

                        // Partial subset intersection with filter_a
                        filter_d.add_terms([ "c", "d" ]);


                        assert!(filter_b.is_subset(&filter_a));
                        assert!(!filter_c.is_subset(&filter_a));
                        assert!(!filter_d.is_subset(&filter_a));
                    }
                }
            )*

            // Recurse through the "tail" of m values
            bloom_filter_tests!(@perms ($($m_tail,)*) ($($k,)*));
        };

        (@perms () ($($k: tt,)*)) => {};
    }

    bloom_filter_tests! {
        valid_m_values => (32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536),
        valid_k_values => (3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
        invalid_m_values => (0, 2, 16, 31, 513, 131072)
    }

    #[test]
    fn test_raises_when_k_is_lt_3() {
        let err = BloomFilter::new(test_key(), BloomFilter::opts().with_hash_function_count(2))
            .expect_err("Expected bloom filter to not create");

        assert_eq!(
            err.to_string(),
            "InvalidFilterTermBits: Expected filter_term_bits to be between 3 and 16. Got: 2"
        )
    }

    #[test]
    fn test_raises_when_k_is_gt_16() {
        let err = BloomFilter::new(test_key(), BloomFilter::opts().with_hash_function_count(17))
            .expect_err("Expected bloom filter to not create");

        assert_eq!(
            err.to_string(),
            "InvalidFilterTermBits: Expected filter_term_bits to be between 3 and 16. Got: 17"
        )
    }

    #[test]
    fn test_accepts_a_single_or_list_of_terms() {
        let mut left = create_test_filter();
        let mut right = create_test_filter();

        left.add_single_term("abc");
        right.add_terms(["abc"]);

        assert!(!left.bits.is_empty());
        assert_eq!(left.bits, right.bits);
    }

    // In practice there will be 1 to k entries. Less than k entries will be in the set
    // in the case that any of the first k slices of the HMAC have the same value.
    #[test]
    fn test_adds_k_entries_to_bits_when_no_collisions() {
        let mut filter = create_test_filter();

        // A term that's known to not have collisions in the first k slices for the test key
        filter.add_single_term("yes");

        assert_eq!(filter.bits.len(), filter.k);
    }
}
