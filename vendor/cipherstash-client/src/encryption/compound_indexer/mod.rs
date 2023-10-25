mod accumulator;
mod cons;
mod prefix_indexer;

use std::fmt::Debug;

use self::prefix_indexer::PrefixIndexer;
use super::{text::TokenFilter, unique_indexer::UniqueIndexer, EncryptionError, Plaintext};
use hmac::Mac;

pub use accumulator::{Accumulator, AccumulatorError};
pub use cons::{ConsArg2, ConsArg3, ConsArg4};

// TODO: This should be in the index schema but avoiding making changes to Vitur for now
#[derive(Debug)]
pub enum Operator {
    Eq,
    StartsWith,
}

#[derive(Debug, Clone)]
pub enum ComposablePlaintext {
    Unit(Plaintext),
    ConsArg2(ConsArg2),
    ConsArg3(ConsArg3),
    ConsArg4(ConsArg4),
}

impl ComposablePlaintext {
    pub fn new(plaintext: impl Into<Plaintext>) -> Self {
        Self::Unit(plaintext.into())
    }

    pub fn try_compose(self, plaintext: impl Into<Plaintext>) -> Result<Self, EncryptionError> {
        let plaintext: Plaintext = plaintext.into();
        match self {
            Self::Unit(a) => Ok(Self::ConsArg2(ConsArg2::new(a, plaintext))),
            Self::ConsArg2(inner) => Ok(Self::ConsArg3(ConsArg3(plaintext, inner))),
            Self::ConsArg3(inner) => Ok(Self::ConsArg4(ConsArg4(plaintext, inner))),
            Self::ConsArg4(_) => Err(EncryptionError::TooManyArguments),
        }
    }

    /// Returns the head of the cons list and the tail of the cons list (if it exists)
    fn pop(self) -> (Self, Option<Self>) {
        match self {
            Self::Unit(head) => (Self::Unit(head), None),
            Self::ConsArg2(ConsArg2(head, tail)) => (Self::Unit(head), Some(Self::Unit(tail))),
            Self::ConsArg3(ConsArg3(head, tail)) => (Self::Unit(head), Some(Self::ConsArg2(tail))),
            Self::ConsArg4(ConsArg4(head, tail)) => (Self::Unit(head), Some(Self::ConsArg3(tail))),
        }
    }
}

impl<T: Into<Plaintext>> From<T> for ComposablePlaintext {
    fn from(plaintext: T) -> Self {
        Self::Unit(plaintext.into())
    }
}

impl<A: Into<Plaintext>, B: Into<Plaintext>> TryFrom<(A, B)> for ComposablePlaintext {
    type Error = EncryptionError;

    fn try_from((a, b): (A, B)) -> Result<Self, Self::Error> {
        Self::Unit(a.into()).try_compose(b)
    }
}

impl<A: Into<Plaintext>, B: Into<Plaintext>, C: Into<Plaintext>> TryFrom<(A, B, C)>
    for ComposablePlaintext
{
    type Error = EncryptionError;

    fn try_from((a, b, c): (A, B, C)) -> Result<Self, Self::Error> {
        Self::Unit(a.into()).try_compose(b)?.try_compose(c)
    }
}

impl<A: Into<Plaintext>, B: Into<Plaintext>, C: Into<Plaintext>, D: Into<Plaintext>>
    TryFrom<(A, B, C, D)> for ComposablePlaintext
{
    type Error = EncryptionError;

    fn try_from((a, b, c, d): (A, B, C, D)) -> Result<Self, Self::Error> {
        Self::Unit(a.into())
            .try_compose(b)?
            .try_compose(c)?
            .try_compose(d)
    }
}

impl TryFrom<ComposablePlaintext> for Plaintext {
    type Error = EncryptionError;

    fn try_from(value: ComposablePlaintext) -> Result<Self, Self::Error> {
        match value {
            ComposablePlaintext::Unit(plaintext) => Ok(plaintext),
            _ => Err(EncryptionError::TooManyArguments),
        }
    }
}

pub enum SupportedOperators {
    Simple(String, Vec<Operator>),

    /// Compound operators so we need to know the field name.
    /// Several combinatons may be supported so we store as a vec.
    Compound(Vec<(String, Vec<Operator>)>),
}

impl SupportedOperators {
    fn to_vec(self) -> Vec<(String, Vec<Operator>)> {
        match self {
            Self::Simple(field, operators) => vec![(field, operators)],
            Self::Compound(fields) => fields,
        }
    }

    fn add(self, other: Self) -> Self {
        Self::Compound(self.to_vec().into_iter().chain(other.to_vec()).collect())
    }
}

/// Trait to represent any index that can be composed with other indexes
/// in a Structured Encryption scheme.
pub trait ComposableIndex: Debug {
    // TODO: Also make a version that doesn't take an accumulator salt
    fn compose_index(
        &self,
        key: [u8; 32],
        plaintext: ComposablePlaintext,
        accumulator: Accumulator,
    ) -> Result<Accumulator, EncryptionError>;

    fn compose_query(
        &self,
        key: [u8; 32],
        plaintext: ComposablePlaintext,
        accumulator: Accumulator,
    ) -> Result<Accumulator, EncryptionError> {
        self.compose_index(key, plaintext, accumulator)
    }

    fn supported_operators(&self) -> SupportedOperators;
}

impl ComposableIndex for Box<dyn ComposableIndex> {
    fn compose_index(
        &self,
        key: [u8; 32],
        plaintext: ComposablePlaintext,
        accumulator: Accumulator,
    ) -> Result<Accumulator, EncryptionError> {
        (**self).compose_index(key, plaintext, accumulator)
    }

    fn supported_operators(&self) -> SupportedOperators {
        (**self).supported_operators()
    }

    fn compose_query(
        &self,
        key: [u8; 32],
        plaintext: ComposablePlaintext,
        accumulator: Accumulator,
    ) -> Result<Accumulator, EncryptionError> {
        (**self).compose_query(key, plaintext, accumulator)
    }
}

#[derive(Debug)]
pub struct ExactIndex {
    field: String,
    token_filters: Vec<TokenFilter>,
}

impl ExactIndex {
    pub fn new(field: impl Into<String>, token_filters: Vec<TokenFilter>) -> Self {
        Self {
            field: field.into(),
            token_filters,
        }
    }
}

impl ComposableIndex for ExactIndex {
    fn compose_index(
        &self,
        key: [u8; 32],
        plaintext: ComposablePlaintext,
        accumulator: Accumulator,
    ) -> Result<Accumulator, EncryptionError> {
        let indexer = UniqueIndexer::new(key, self.token_filters.to_vec());
        let plaintext: Plaintext = plaintext.try_into()?;

        match accumulator {
            Accumulator::Term(term) => {
                let mut mac = indexer.create_hmac()?;
                indexer.encrypt_into_hmac(&mut mac, &plaintext)?;
                mac.update(term.as_ref());
                Ok(Accumulator::Term(mac.finalize().into_bytes().to_vec()))
            }
            Accumulator::Terms(terms) => terms
                .into_iter()
                .map(|term| {
                    let mut mac = indexer.create_hmac()?;
                    indexer.encrypt_into_hmac(&mut mac, &plaintext)?;
                    mac.update(term.as_ref());
                    Ok(mac.finalize().into_bytes().to_vec())
                })
                .collect::<Result<Vec<_>, EncryptionError>>()
                .map(Accumulator::Terms),
        }
    }

    fn supported_operators(&self) -> SupportedOperators {
        SupportedOperators::Simple(self.field.to_string(), vec![Operator::Eq])
    }
}

#[derive(Debug)]
pub struct PrefixIndex {
    field: String,
    token_filters: Vec<TokenFilter>,
    min_length: usize,
    max_length: usize,
}

impl PrefixIndex {
    pub fn new(
        field: impl Into<String>,
        token_filters: Vec<TokenFilter>,
    ) -> Self {
        Self::new_with_opts(field, token_filters, 3, 10)
    }

    pub fn new_with_opts(
        field: impl Into<String>,
        token_filters: Vec<TokenFilter>,
        min_length: usize,
        max_length: usize,
    ) -> Self {
        Self {
            field: field.into(),
            token_filters,
            min_length,
            max_length,
        }
    }
}

impl ComposableIndex for PrefixIndex {
    fn compose_index(
        &self,
        key: [u8; 32],
        plaintext: ComposablePlaintext,
        accumulator: Accumulator,
    ) -> Result<Accumulator, EncryptionError> {
        let indexer = PrefixIndexer::new(
            key,
            self.token_filters.to_vec(),
            self.min_length,
            self.max_length,
        );
        let plaintext: Plaintext = plaintext.try_into()?;

        match accumulator {
            Accumulator::Term(term) => indexer.index_with_salt(&plaintext, term),
            Accumulator::Terms(terms) => {
                terms
                    .into_iter()
                    .fold(Ok(Accumulator::empty()), |acc, term| {
                        if let Ok(acc) = acc {
                            indexer
                                .index_with_salt(&plaintext, term)
                                .map(|out| acc.add(out))
                        } else {
                            acc
                        }
                    })
            }
        }
    }

    // TODO: Dry this up
    fn compose_query(
        &self,
        key: [u8; 32],
        plaintext: ComposablePlaintext,
        accumulator: Accumulator,
    ) -> Result<Accumulator, EncryptionError> {
        let indexer = PrefixIndexer::new(
            key,
            self.token_filters.to_vec(),
            self.min_length,
            self.max_length,
        );
        let plaintext: Plaintext = plaintext.try_into()?;

        match accumulator {
            Accumulator::Term(term) => indexer.query_with_salt(&plaintext, term),
            _ => Err(AccumulatorError::MultipleTermsFound)?,
        }
    }

    fn supported_operators(&self) -> SupportedOperators {
        SupportedOperators::Simple(self.field.to_string(), vec![Operator::StartsWith])
    }
}

#[derive(Debug)]
pub struct CompoundIndexOfTwo<A, B>
where
    A: ComposableIndex,
    B: ComposableIndex,
{
    indexes: (A, B), // TODO: remove the indexes key
}

impl<A, B> CompoundIndexOfTwo<A, B>
where
    A: ComposableIndex,
    B: ComposableIndex,
{
    pub fn new(a: A, b: B) -> Self {
        Self { indexes: (a, b) }
    }
}

impl<A: ComposableIndex, B: ComposableIndex> ComposableIndex for CompoundIndexOfTwo<A, B> {
    fn compose_index(
        &self,
        key: [u8; 32],
        inputs: ComposablePlaintext,
        accumulator: Accumulator,
    ) -> Result<Accumulator, EncryptionError> {
        let (head, tail) = inputs.pop();
        // TODO: Expand the keys with HKDF

        self.indexes.0.compose_index(
            key,
            head,
            self.indexes.1.compose_index(
                key,
                tail.ok_or(EncryptionError::TooFewArguments)?,
                accumulator,
            )?,
        )
    }

    fn compose_query(
        &self,
        key: [u8; 32],
        inputs: ComposablePlaintext,
        accumulator: Accumulator,
        // TODO: It would be nice to return an ExactlyOne<Accumulator> here
        // In fact, it should take that, too!
    ) -> Result<Accumulator, EncryptionError> {
        let (head, tail) = inputs.pop();
        // TODO: Expand the keys with HKDF

        self.indexes.0.compose_query(
            key,
            head,
            self.indexes.1.compose_query(
                key,
                tail.ok_or(EncryptionError::TooFewArguments)?,
                accumulator,
            )?,
        )
    }

    fn supported_operators(&self) -> SupportedOperators {
        self.indexes
            .0
            .supported_operators()
            .add(self.indexes.1.supported_operators())
    }
}

#[derive(Debug)]
pub struct CompoundIndex<I: ComposableIndex>(I);

impl<I: ComposableIndex> CompoundIndex<I> {
    pub fn new(index: I) -> Self {
        Self(index)
    }

    pub fn and<J: ComposableIndex>(self, other: J) -> CompoundIndex<CompoundIndexOfTwo<J, I>> {
        CompoundIndex(CompoundIndexOfTwo::new(other, self.0))
    }
}

// FIXME: This is a bit of a hack to get the derive traits working
impl From<(String, String)> for Box<dyn ComposableIndex> {
    fn from(value: (String, String)) -> Self {
        let (name, index_type) = value;
        match index_type.as_str() {
            "exact" => Box::new(ExactIndex::new(name, vec![])),
            "prefix" => Box::new(PrefixIndex::new(name, vec![])),
            _ => panic!("Unknown index type"),
        }
    }
}

impl From<((String, String), (String, String))> for Box<dyn ComposableIndex> {
    fn from(value: ((String, String), (String, String))) -> Self {
        let (a, (name, index_type)) = value;
        let start: Box<dyn ComposableIndex> = a.into();
        match index_type.as_str() {
            "exact" => Box::new(
                CompoundIndex::new(
                    ExactIndex::new(name, vec![])
                ).and(start)
            ),
            "prefix" => Box::new(
                CompoundIndex::new(
                    PrefixIndex::new(name, vec![])
                ).and(start)
            ),
            _ => panic!("Unknown index type"),
        }
    }
}

impl From<((String, String), (String, String), (String, String))> for Box<dyn ComposableIndex> {
    fn from(value: ((String, String), (String, String), (String, String))) -> Self {
        let (a, b, (name, index_type)) = value;
        let start: Box<dyn ComposableIndex> = (a, b).into();
        match index_type.as_str() {
            "exact" => Box::new(
                CompoundIndex::new(
                    ExactIndex::new(name, vec![])
                ).and(start)
            ),
            "prefix" => Box::new(
                CompoundIndex::new(
                    PrefixIndex::new(name, vec![])
                ).and(start)
            ),
            _ => panic!("Unknown index type"),
        }
    }
}

impl<I: ComposableIndex> ComposableIndex for CompoundIndex<I> {
    fn compose_index(
        &self,
        key: [u8; 32],
        plaintext: ComposablePlaintext,
        accumulator: Accumulator,
    ) -> Result<Accumulator, EncryptionError> {
        self.0.compose_index(key, plaintext, accumulator)
    }

    fn compose_query(
        &self,
        key: [u8; 32],
        plaintext: ComposablePlaintext,
        accumulator: Accumulator,
    ) -> Result<Accumulator, EncryptionError> {
        self.0.compose_query(key, plaintext, accumulator)
    }

    fn supported_operators(&self) -> SupportedOperators {
        self.0.supported_operators()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_exact() -> Result<(), Box<dyn std::error::Error>> {
        let index = ExactIndex::new("email", vec![]);
        let result = index.compose_index(
            [1; 32],
            "foo@bar.com".try_into()?,
            Accumulator::from_salt("user#email"),
        )?;

        assert_eq!(result.terms().len(), 1);

        Ok(())
    }

    #[test]
    fn test_single_exact_in_a_compound() -> Result<(), Box<dyn std::error::Error>> {
        let index = CompoundIndex::new(ExactIndex::new("email", vec![]));
        let result = index.compose_index(
            [1; 32],
            "foo@bar.com".try_into()?,
            Accumulator::from_salt("user#email"),
        )?;

        assert_eq!(result.terms().len(), 1);

        Ok(())
    }

    #[test]
    fn test_two_exact_indexes() -> Result<(), Box<dyn std::error::Error>> {
        let index = CompoundIndex::new(ExactIndex::new("email", vec![]))
            .and(ExactIndex::new("name", vec![]));

        let result = index.compose_index(
            [1; 32],
            ("foo@bar.com", "Person").try_into()?,
            // TODO: The compound index already has the field names
            // This is a leaky abstraction
            Accumulator::from_salt("user#email/name"),
        )?;
        assert_eq!(result.terms().len(), 1);

        Ok(())
    }

    #[test]
    fn test_one_exact_one_prefix() -> Result<(), Box<dyn std::error::Error>> {
        let index = CompoundIndex::new(ExactIndex::new("email", vec![])).and(PrefixIndex::new(
            "name",
            vec![],
        ));

        let result = index.compose_index(
            [1; 32],
            ("foo@bar.com", "Person").try_into()?,
            Accumulator::from_salt("user#email/name"),
        )?;
        assert_eq!(result.terms().len(), 4);

        Ok(())
    }

    #[test]
    fn test_three_exact_indexes() -> Result<(), Box<dyn std::error::Error>> {
        let index = CompoundIndex::new(ExactIndex::new("email", vec![]))
            .and(ExactIndex::new("email", vec![]))
            .and(ExactIndex::new("active", vec![]));

        let result = index.compose_index(
            [1; 32],
            ("foo@bar.com", "Person", true).try_into()?,
            Accumulator::from_salt("user#email/name/active"),
        )?;
        assert_eq!(result.terms().len(), 1);

        Ok(())
    }

    #[test]
    fn test_one_exact_one_prefix_one_exact() -> Result<(), Box<dyn std::error::Error>> {
        let index = CompoundIndex::new(ExactIndex::new("email", vec![]))
            .and(PrefixIndex::new("name", vec![]))
            .and(ExactIndex::new("login-count", vec![]));

        let result = index.compose_index(
            [1; 32],
            ("foo@bar.com", "Person", 100i32).try_into()?,
            Accumulator::from_salt("user#email/name/login-count"),
        )?;
        assert_eq!(result.terms().len(), 4);

        Ok(())
    }

    #[test]
    fn test_one_exact_one_prefix_one_prefix() -> Result<(), Box<dyn std::error::Error>> {
        let index = CompoundIndex::new(ExactIndex::new("email", vec![]))
            .and(PrefixIndex::new("first-name", vec![]))
            .and(PrefixIndex::new("last-name", vec![]));

        let result = index.compose_index(
            [1; 32],
            ("foo@bar.com", "Daniel", "Draper").try_into()?,
            Accumulator::from_salt("user#email/first-name/last-name"),
        )?;
        assert_eq!(result.terms().len(), 16);

        Ok(())
    }
}
