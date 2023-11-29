//! Contains tools and structs for processing text to be inserted into the database

use serde::{Deserialize, Serialize};

/// Different methods for generating tokens used for full text search
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Tokenizer {
    EdgeNgram {
        min_gram: usize,
        max_gram: usize,
    },
    #[serde(rename_all = "camelCase")]
    Ngram {
        token_length: usize,
    },
    Standard,
}

impl Tokenizer {
    /// Process text and return the tokens based on the specific tokenizer
    pub fn process(&self, text: String) -> Vec<String> {
        match self {
            Tokenizer::Ngram { token_length } => process_ngram(text, *token_length),

            Tokenizer::Standard => process_standard(text),

            Tokenizer::EdgeNgram { min_gram, max_gram } => {
                process_all_edge_ngrams(text, *min_gram, *max_gram)
            }
        }
    }
}

fn process_ngram(text: String, token_length: usize) -> Vec<String> {
    let chars = text.chars().collect::<Vec<_>>();

    if chars.len() < token_length {
        return vec![];
    }

    let mut grams: Vec<String> = vec![];

    for i in 0..=(chars.len() - token_length) {
        grams.push(chars[i..i + token_length].iter().collect());
    }

    grams
}

fn process_standard(text: String) -> Vec<String> {
    text.split(&[' ', ',', ';', ':', '!'])
        .map(|x| x.into())
        .collect()
}

#[allow(dead_code)]
pub(super) fn split_on_whitespace(text: String) -> Vec<String> {
    text.split_whitespace().map(|s| s.to_string()).collect()
}

/// Simpler version of an edgegram which does not perform any filtering on the text
pub(super) fn process_all_edge_ngrams_raw(
    text: String,
    min_gram: usize,
    max_gram: usize,
) -> Vec<String> {
    let mut grams: Vec<String> = vec![];
    let chars: Vec<char> = text.chars().collect();

    if chars.is_empty() {
        return grams;
    }

    for i in 0..=chars.len() - 1 {
        let current_gram_len = i + 1;

        if min_gram <= current_gram_len && current_gram_len <= max_gram {
            grams.push(chars[0..=i].iter().collect());
        }
    }

    grams
}

/// Returns all edgegrams longer than min_gram and shorter than max_gram for each word in a given text.
/// For example if the text is "Thomas Lovelace", the edgegrams are:
/// ["T", "Th", "Tho", "Thom", "Thoma", "Thomas", "L", "Lo", "Lov", "Love", "Lovel", "Lovelace"]
/// If min_gram = 2 and max_gram = 4, the edgegrams are:
/// ["Th", "Tho", "Thom", "Thoma", "L", "Lo", "Lov", "Love"]
pub(super) fn process_all_edge_ngrams(
    text: String,
    min_gram: usize,
    max_gram: usize,
) -> Vec<String> {
    let mut grams: Vec<String> = vec![];
    let chars: Vec<char> = text.chars().collect();

    if chars.is_empty() {
        return grams;
    }

    let mut current_word_start = 0;
    for i in 0..=chars.len() - 1 {
        let current_char = chars[i];
        let current_gram_len = i - current_word_start + 1;

        // FIXME: Tokenizers shouldn't strip characters, this should be done by a char filter
        if !current_char.is_alphabetic() {
            current_word_start = i + 1;
        } else if min_gram <= current_gram_len && current_gram_len <= max_gram {
            grams.push(chars[current_word_start..=i].iter().collect());
        }
    }

    grams
}

/// Different methods for transforming text or tokens
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TokenFilter {
    Upcase,
    Downcase,
}

impl TokenFilter {
    pub fn process_single(&self, text: String) -> String {
        match self {
            TokenFilter::Upcase => text.to_uppercase(),
            TokenFilter::Downcase => text.to_lowercase(),
        }
    }

    /// Process text based on a specific token filter
    pub fn process(&self, text: Vec<String>) -> Vec<String> {
        text.into_iter()
            .map(|text| self.process_single(text))
            .collect()
    }
}

// Purpose built function to remove chars from the beginning and end of a plaintext string.
// Added for using with the match indexers to strip % and _ operators from plaintext values.
// Consider removing if no longer needed after completing this card.
// https://www.notion.so/cipherstash/WIP-Driver-more-robust-LIKE-op-handling-7ccf85c873374fb68ad651816f6bd9f6?pvs=4
pub fn char_filter_prefix_and_suffix(plaintext: &str, chars_to_filter: &[char]) -> String {
    let mut result = String::from(plaintext);
    for ch in chars_to_filter {
        if let Some(stripped) = result.strip_suffix(*ch) {
            result = stripped.to_string();
        }
        if let Some(stripped) = result.strip_prefix(*ch) {
            result = stripped.to_string();
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::{char_filter_prefix_and_suffix, TokenFilter, Tokenizer};

    #[test]
    fn test_standard() {
        let output = Tokenizer::Standard.process("Hello from Ada Lovelace".into());

        assert_eq!(output, vec!["Hello", "from", "Ada", "Lovelace"]);
    }

    #[test]
    fn test_ngram() {
        let output = Tokenizer::Ngram { token_length: 3 }.process("Lovelace".into());
        assert_eq!(output, vec!["Lov", "ove", "vel", "ela", "lac", "ace"]);
    }

    #[test]
    fn test_ngram_equal_length() {
        let output = Tokenizer::Ngram { token_length: 4 }.process("Love".into());
        assert_eq!(output, vec!["Love"]);
    }

    #[test]
    fn test_ngram_shorter_length() {
        let output = Tokenizer::Ngram { token_length: 4 }.process("Lov".into());
        assert_eq!(output, Vec::<String>::new());
    }

    #[test]
    fn test_ngram_zero_length() {
        let output = Tokenizer::Ngram { token_length: 0 }.process("Lovelace".into());
        assert_eq!(output, vec!["", "", "", "", "", "", "", "", ""]);
    }

    #[test]
    fn test_edge_ngram_empty_input() {
        let tokenizer = Tokenizer::EdgeNgram {
            min_gram: 2,
            max_gram: 10,
        };

        let output = tokenizer.process("".to_string());

        assert_eq!(output, Vec::<String>::new())
    }

    #[test]
    fn test_edge_ngram_single_word() {
        let tokenizer = Tokenizer::EdgeNgram {
            min_gram: 1,
            max_gram: 10,
        };

        let output = tokenizer.process("Thomas".to_string());

        assert_eq!(output, vec!["T", "Th", "Tho", "Thom", "Thoma", "Thomas"])
    }

    #[test]
    fn test_edge_ngram_multiple_words() {
        let tokenizer = Tokenizer::EdgeNgram {
            min_gram: 1,
            max_gram: 10,
        };

        let output = tokenizer.process("Heath Jones".to_string());

        assert_eq!(
            output,
            vec!["H", "He", "Hea", "Heat", "Heath", "J", "Jo", "Jon", "Jone", "Jones"]
        )
    }

    #[test]
    fn test_edge_ngram_min_gram_2() {
        let tokenizer = Tokenizer::EdgeNgram {
            min_gram: 2,
            max_gram: 10,
        };

        let output = tokenizer.process("Heath Jones".to_string());

        assert_eq!(
            output,
            vec!["He", "Hea", "Heat", "Heath", "Jo", "Jon", "Jone", "Jones"]
        )
    }

    #[test]
    fn test_edge_ngram_max_gram_lt_word_len() {
        let tokenizer = Tokenizer::EdgeNgram {
            min_gram: 1,
            max_gram: 2,
        };

        let output = tokenizer.process("Heath Jones".to_string());

        assert_eq!(output, vec!["H", "He", "J", "Jo"])
    }

    #[test]
    #[ignore = "This test is failing because the tokenizer is stripping non-alpha chars"]
    fn test_edge_ngram_email_address() {
        let tokenizer = Tokenizer::EdgeNgram {
            min_gram: 3,
            max_gram: 10,
        };

        let output = tokenizer.process("foo@bar.com".to_string());

        assert_eq!(
            output,
            vec![
                "foo",
                "foo@",
                "foo@b",
                "foo@b",
                "foo@bar",
                "foo@bar",
                "foo@bar.",
                "foo@bar.c",
                "foo@bar.co"
            ]
        );
    }

    #[test]
    fn test_edge_ngram_max_eq_min() {
        let tokenizer = Tokenizer::EdgeNgram {
            min_gram: 3,
            max_gram: 3,
        };

        let output = tokenizer.process("Heath Jones".to_string());

        assert_eq!(output, vec!["Hea", "Jon"])
    }

    #[test]
    fn test_edge_ngram_max_lt_min() {
        let tokenizer = Tokenizer::EdgeNgram {
            min_gram: 4,
            max_gram: 3,
        };

        let output = tokenizer.process("Heath Jones".to_string());

        assert_eq!(output, Vec::<String>::new())
    }

    #[test]
    fn test_edge_ngram_min_0() {
        let tokenizer = Tokenizer::EdgeNgram {
            min_gram: 0,
            max_gram: 1,
        };

        let output = tokenizer.process("Heath Jones".to_string());

        assert_eq!(output, vec!["H", "J"])
    }

    #[test]
    fn test_edge_ngram_min_and_max_0() {
        let tokenizer = Tokenizer::EdgeNgram {
            min_gram: 0,
            max_gram: 0,
        };

        let output = tokenizer.process("Heath Jones".to_string());

        assert_eq!(output, Vec::<String>::new())
    }

    #[test]
    fn test_edge_ngram_words_of_various_lengths() {
        let tokenizer = Tokenizer::EdgeNgram {
            min_gram: 2,
            max_gram: 4,
        };

        let output = tokenizer.process("a bb ccc dddd eeeee".to_string());

        assert_eq!(
            output,
            vec!["bb", "cc", "ccc", "dd", "ddd", "dddd", "ee", "eee", "eeee"]
        )
    }

    #[test]
    fn test_edge_ngram_non_alpha_chars() {
        let tokenizer = Tokenizer::EdgeNgram {
            min_gram: 1,
            max_gram: 2,
        };

        let output = tokenizer.process("123!?hi 🤨ño\\".to_string());

        assert_eq!(output, vec!["h", "hi", "ñ", "ño"])
    }

    #[test]
    fn test_downcase() {
        let output = TokenFilter::Downcase.process(vec!["HeLLOWorlD".into()]);
        assert_eq!(output, vec!["helloworld"]);
    }

    #[test]
    fn test_upcase() {
        let output = TokenFilter::Upcase.process(vec!["HeLLOWorlD".into()]);
        assert_eq!(output, vec!["HELLOWORLD"]);
    }

    #[test]
    fn test_char_filter_removes_prefix_and_suffix() {
        let plaintext_mixed_ops = "_testing%";
        let plaintext_underscore_op = "_testing_";
        let plaintext_percentage_ops = "%testing%";
        let chars = ['%', '_'];

        let mixed_op_output = char_filter_prefix_and_suffix(plaintext_mixed_ops, &chars);
        let underscore_op_output = char_filter_prefix_and_suffix(plaintext_underscore_op, &chars);
        let percentage_op_output = char_filter_prefix_and_suffix(plaintext_percentage_ops, &chars);

        assert_eq!(mixed_op_output, "testing");
        assert_eq!(underscore_op_output, "testing");
        assert_eq!(percentage_op_output, "testing");
    }

    #[test]
    fn test_longest_edgegram() {
        let output = super::split_on_whitespace("Thomas".to_string());
        assert_eq!(output, vec!["Thomas"]);
    }

    #[test]
    fn test_longest_edgegram_multiple_words() {
        let output = super::split_on_whitespace("Thomas Lovelace".to_string());
        assert_eq!(output, vec!["Thomas", "Lovelace"]);
    }
}
