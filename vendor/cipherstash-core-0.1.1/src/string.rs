use lazy_static::lazy_static;
use num_bigint::{BigUint, ToBigUint};
use regex::Regex;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OrderiseStringError {
    #[error("Can only order strings that are pure ASCII")]
    NotAscii,
}

pub fn orderise_string(s: &str) -> Result<Vec<u64>, OrderiseStringError> {
    if !s.is_ascii() {
        return Err(OrderiseStringError::NotAscii);
    }

    lazy_static! {
        static ref NON_ALPHANUMERIC_OR_SPACE_REGEX: Regex =
            Regex::new("[^a-z0-9[:space:]]+").unwrap();
    }

    lazy_static! {
        static ref SPACE_REGEX: Regex = Regex::new("[[:space:]]+").unwrap();
    }

    lazy_static! {
        static ref DIGIT_REGEX: Regex = Regex::new("[0-9]").unwrap();
    }

    // This all very much relies on ASCII character numbering.  A copy of `ascii`(7)
    // up on a convenient terminal may assist in understanding what's going
    // on here.

    // First up, let's transmogrify the string we were given into one that only contains
    // a controlled subset of characters, that we can easily map into a smaller numeric
    // space.

    let mut s = s.to_lowercase();

    // Any group of rando characters sort at the end.
    s = NON_ALPHANUMERIC_OR_SPACE_REGEX
        .replace_all(&s, "~")
        .to_string();

    // Any amount of whitespace comes immediately after letters.
    s = SPACE_REGEX.replace_all(&s, "{").to_string();

    // Numbers come after spaces.
    s = DIGIT_REGEX.replace_all(&s, "|").to_string();

    // Next, we turn that string of characters into a "packed" number that represents the
    // whole string, but in a more compact form than would be used if each character took
    // up the full seven or eight bits used by regular ASCII.
    let mut n = s
        .bytes()
        // 'a' => 1, 'b' => 2, ..., 'z' => 27, '{' => 28, '|' => 29,
        // '}' => 30 (unused), '~' => 31.  0 is kept as "no character" so
        // that short strings sort before longer ones.
        .map(|c| BigUint::from(c - 96))
        // Turn the whole thing into one giant number, with each character
        // occupying five bits of said number.
        .fold(0.to_biguint().unwrap(), |i, c| (i << 5) + c);

    // Thirdly, we need to turn the number into one whose in-memory representation
    // has a length in bits that is a multiple of 64.  This is to ensure that
    // the first character has the most-significant bits possible, so it
    // sorts the highest.
    n <<= 64 - (s.len() * 5) % 64;

    let mut terms = Vec::new();

    let two_pow_64 = 2.to_biguint().unwrap().pow(64);

    // And now, semi-finally, we can turn all that gigantic mess into a vec of u64 terms.
    while n > 0.to_biguint().unwrap() {
        // Unwrapping is fine here because we'll end up with a number that
        // fits into a u64.
        let term = (&n % &two_pow_64).try_into().unwrap();

        terms.insert(0, term);

        n >>= 64;
    }

    // Only six ORE ciphertexts can fit into the database.
    terms.truncate(6);

    Ok(terms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::{fs, path::Path};

    #[test]
    fn test_orderise_string_non_ascii() {
        let result = orderise_string("Jalapeño");

        assert!(matches!(result, Err(OrderiseStringError::NotAscii)));

        let message = result.err().unwrap().to_string();

        assert_eq!(message, "Can only order strings that are pure ASCII")
    }

    #[test]
    // Asserts that output from orderise_string matches output from the ruby client.
    // Tests against a file that contains a snapshot of results from the ruby client.
    fn test_orderise_string_gives_same_output_as_ruby_clint() {
        #[derive(Deserialize, Debug)]
        struct TestCase {
            input: String,
            output: Vec<u64>,
        }

        let case_file_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("./orderise_string_test_cases.json");
        let json_str = fs::read_to_string(case_file_path).expect("couldn't read test case file");
        let test_cases: Vec<TestCase> =
            serde_json::from_str(&json_str).expect("couldn't parse test cases");

        for test_case in test_cases {
            let result = orderise_string(&test_case.input);

            assert!(
                result.is_ok(),
                "Expected orderise_string to succeed given {:?}, but got error: {:?}",
                &test_case.input,
                result
            );

            assert_eq!(
                result.unwrap(),
                test_case.output,
                "\n orderise_string didn't match for input: {:?}",
                test_case.input
            );
        }
    }
}
