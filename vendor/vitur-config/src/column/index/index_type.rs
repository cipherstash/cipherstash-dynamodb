use serde::{Deserialize, Serialize};

use crate::{operator::Operator, ColumnType};

use super::{TokenFilter, Tokenizer};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum IndexType {
    Ore,
    Match {
        tokenizer: Tokenizer,
        token_filters: Vec<TokenFilter>,
        k: usize,
        m: usize,
        /// Indicates if the original term should be added as a term
        /// which allows a match index to be used for equality
        include_original: bool,
    },
    /// This is called Unique because a Hash index must always
    /// have a unique constraint on it but it is technically a Determinstic
    /// index. Naming is hard.
    Unique {
        #[serde(default)]
        token_filters: Vec<TokenFilter>,
    },
}

impl IndexType {
    /// Returns true or false based on the below:
    ///
    /// Non string type indexes support:
    ///
    /// Ore: Eq | Lt | Lte | Gt | Gte,
    /// Unique: Eq
    ///
    /// String type indexes support:
    ///
    /// Match: Like | ILike
    /// Ore: Lt | Lte | Gt | Gte,
    /// Unique: Eq
    ///
    pub fn supports(&self, op: &Operator, cast_type: &ColumnType) -> bool {
        use Operator::*;
        // returns a bool

        match (self, op, cast_type) {
            (Self::Ore, Eq, ColumnType::Utf8Str) => false,
            (Self::Ore, Lt | Lte | Gt | Gte, _) => true,
            (Self::Ore, Eq, _) => true,
            (Self::Ore, Like | ILike | Unsupported, _) => false,

            (Self::Match { .. }, Like | ILike, ColumnType::Utf8Str) => true,
            (Self::Match { .. }, Like | ILike | Eq | Lt | Lte | Gt | Gte | Unsupported, _) => false,

            (Self::Unique { .. }, Eq, _) => true,
            (Self::Unique { .. }, Like | ILike | Lt | Lte | Gt | Gte | Unsupported, _) => false,
        }
    }

    pub fn supported_operations(&self, cast_type: &ColumnType) -> Vec<Operator> {
        use Operator::*;

        match self {
            IndexType::Ore => match cast_type {
                ColumnType::Utf8Str => vec![Lt, Lte, Gt, Gte],
                _ => vec![Eq, Lt, Lte, Gt, Gte],
            },
            IndexType::Match { .. } => vec![Like],
            IndexType::Unique { .. } => vec![Eq],
        }
    }

    pub fn is_orderable(&self) -> bool {
        matches!(self, Self::Ore)
    }

    /// String identifier for the index type.
    /// Useful when naming columns
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ore => "ore",
            Self::Match { .. } => "match",
            Self::Unique { .. } => "unique",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::column::Index;

    fn non_string_types() -> Vec<ColumnType> {
        vec![
            ColumnType::SmallInt,
            ColumnType::BigInt,
            ColumnType::Int,
            ColumnType::Boolean,
            ColumnType::Date,
            ColumnType::Decimal,
            ColumnType::Float,
            ColumnType::Timestamp,
        ]
    }

    fn string_type() -> ColumnType {
        ColumnType::Utf8Str
    }

    #[test]
    fn test_operator_support_ore() {
        let index_type = Index::new_ore();

        // Non String types
        non_string_types().into_iter().for_each(|t| {
            // Supports range and eq ops for non string types
            assert!(index_type.supports(&Operator::Eq, &t));
            assert!(index_type.supports(&Operator::Lt, &t));
            assert!(index_type.supports(&Operator::Lte, &t));
            assert!(index_type.supports(&Operator::Gt, &t));
            assert!(index_type.supports(&Operator::Gte, &t));

            // Does not support
            assert!(!IndexType::Ore.supports(&Operator::Like, &t));
            assert!(!IndexType::Ore.supports(&Operator::ILike, &t));
            assert!(!IndexType::Ore.supports(&Operator::Unsupported, &t));
        });

        // Supports range for string types
        assert!(index_type.supports(&Operator::Lt, &string_type()));
        assert!(index_type.supports(&Operator::Lte, &string_type()));
        assert!(index_type.supports(&Operator::Gt, &string_type()));
        assert!(index_type.supports(&Operator::Gte, &string_type()));

        // Does not support for string types
        assert!(!index_type.supports(&Operator::Eq, &string_type()));
        assert!(!IndexType::Ore.supports(&Operator::Like, &string_type()));
        assert!(!IndexType::Ore.supports(&Operator::ILike, &string_type()));
        assert!(!IndexType::Ore.supports(&Operator::Unsupported, &string_type()));
    }

    #[test]
    fn test_operator_support_match() {
        let index_type = Index::new_match();

        // Supports Like on string type
        assert!(index_type.supports(&Operator::Like, &string_type()));
        assert!(index_type.supports(&Operator::ILike, &string_type()));

        // Doesn't support on string types
        assert!(!index_type.supports(&Operator::Eq, &string_type()));
        assert!(!index_type.supports(&Operator::Lt, &string_type()));
        assert!(!index_type.supports(&Operator::Lte, &string_type()));
        assert!(!index_type.supports(&Operator::Gt, &string_type()));
        assert!(!index_type.supports(&Operator::Gte, &string_type()));
        assert!(!index_type.supports(&Operator::Unsupported, &string_type()));

        // Doesn't support on non string types
        non_string_types().into_iter().for_each(|t| {
            assert!(!index_type.supports(&Operator::Like, &t));
            assert!(!index_type.supports(&Operator::ILike, &t));
            assert!(!index_type.supports(&Operator::Eq, &t));
            assert!(!index_type.supports(&Operator::Lt, &t));
            assert!(!index_type.supports(&Operator::Lte, &t));
            assert!(!index_type.supports(&Operator::Gt, &t));
            assert!(!index_type.supports(&Operator::Gte, &t));
            assert!(!index_type.supports(&Operator::Unsupported, &t));
        });
    }

    #[test]
    fn test_operator_support_unique() {
        let index_type = Index::new_unique();

        // Supports Eq on all types
        assert!(index_type.supports(&Operator::Eq, &string_type()));

        non_string_types().into_iter().for_each(|t| {
            assert!(index_type.supports(&Operator::Eq, &t));
        });

        // Doesn't support
        non_string_types().into_iter().for_each(|t| {
            assert!(!index_type.supports(&Operator::Like, &t));
            assert!(!index_type.supports(&Operator::ILike, &t));
            assert!(!index_type.supports(&Operator::Unsupported, &t));
            assert!(!index_type.supports(&Operator::Lt, &t));
            assert!(!index_type.supports(&Operator::Lte, &t));
            assert!(!index_type.supports(&Operator::Gt, &t));
            assert!(!index_type.supports(&Operator::Gte, &t));
        });

        assert!(!index_type.supports(&Operator::Like, &string_type()));
        assert!(!index_type.supports(&Operator::ILike, &string_type()));
        assert!(!index_type.supports(&Operator::Unsupported, &string_type()));
        assert!(!index_type.supports(&Operator::Lt, &string_type()));
        assert!(!index_type.supports(&Operator::Lte, &string_type()));
        assert!(!index_type.supports(&Operator::Gt, &string_type()));
        assert!(!index_type.supports(&Operator::Gte, &string_type()));
    }

    #[test]
    fn test_is_orderable() {
        assert!(!Index::new_match().is_orderable());
        assert!(!Index::new_unique().is_orderable());
        assert!(Index::new_ore().is_orderable());
    }
}
