use crate::encryption::IndexTerm;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AccumulatorError {
    #[error("Invalid term length")]
    InvalidTermLength,
    #[error("Empty accumulator")]
    EmptyAccumulator,
    #[error("Multiple terms found")]
    MultipleTermsFound,
}

#[derive(Debug)]
pub enum Accumulator {
    Term(Vec<u8>),
    Terms(Vec<Vec<u8>>),
}

pub struct ExactlyOneAccumulator(Accumulator);

impl ExactlyOneAccumulator {
    pub fn term(self) -> Vec<u8> {
        match self.0 {
            Accumulator::Term(term) => term,
            Accumulator::Terms(terms) => {
                unreachable!("Expected exactly one term, found {:?}", terms)
            }
        }
    }

    pub fn into_inner(self) -> Accumulator {
        self.0
    }

    pub fn truncate(self, term_length: usize) -> Result<Self, AccumulatorError> {
        Ok(Self(self.0.truncate(term_length)?))
    }
}

impl Accumulator {
    pub fn from_salt<S: AsRef<[u8]>>(salt: S) -> Self {
        Self::Term(salt.as_ref().to_vec())
    }

    pub fn truncate(self, term_length: usize) -> Result<Self, AccumulatorError> {
        if term_length > 32 {
            Err(AccumulatorError::InvalidTermLength)?
        }

        match self {
            Accumulator::Term(term) => Ok(Accumulator::Term(term[..term_length].to_vec())),
            Accumulator::Terms(terms) => Ok(Accumulator::Terms(
                terms
                    .into_iter()
                    .map(|term| term[..term_length].to_vec())
                    .collect(),
            )),
        }
    }

    pub fn terms(self) -> Vec<Vec<u8>> {
        match self {
            Accumulator::Term(term) => vec![term],
            Accumulator::Terms(terms) => terms,
        }
    }

    pub(crate) fn empty() -> Self {
        Self::Terms(vec![])
    }

    /// Return the accumulator term, only if there is exactly one term in the accumulator
    pub fn exactly_one(self) -> Result<ExactlyOneAccumulator, AccumulatorError> {
        match self {
            Accumulator::Term(_) => Ok(ExactlyOneAccumulator(self)),
            Accumulator::Terms(terms) => {
                if terms.is_empty() {
                    Err(AccumulatorError::EmptyAccumulator)
                } else {
                    Err(AccumulatorError::MultipleTermsFound)
                }
            }
        }
    }

    pub(super) fn add(self, other: Self) -> Self {
        match self {
            Accumulator::Term(term) => Accumulator::Terms([vec![term], other.terms()].concat()),
            Accumulator::Terms(terms) => Accumulator::Terms([terms, other.terms()].concat()),
        }
    }
}

impl From<Accumulator> for IndexTerm {
    fn from(acc: Accumulator) -> Self {
        match acc {
            Accumulator::Term(term) => IndexTerm::Binary(term),
            Accumulator::Terms(terms) => IndexTerm::BinaryVec(terms),
        }
    }
}

impl From<ExactlyOneAccumulator> for IndexTerm {
    fn from(acc: ExactlyOneAccumulator) -> Self {
        IndexTerm::Binary(acc.term())
    }
}
