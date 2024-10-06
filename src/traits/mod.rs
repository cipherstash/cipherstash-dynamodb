use crate::crypto::{SealError, Unsealed};
pub use crate::encrypted_table::{TableAttribute, TryFromTableAttr};
use cipherstash_client::encryption::EncryptionError;
pub use cipherstash_client::{
    credentials::{service_credentials::ServiceToken, Credentials},
    encryption::{
        compound_indexer::{
            ComposableIndex, ComposablePlaintext, CompoundIndex, ExactIndex, PrefixIndex,
        },
        Encryption, Plaintext, PlaintextNullVariant, TryFromPlaintext,
    },
};

mod primary_key;
use miette::Diagnostic;
pub use primary_key::*;

use std::{
    borrow::Cow,
    fmt::{Debug, Display},
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SingleIndex {
    Exact,
    Prefix,
}

impl Display for SingleIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exact => f.write_str("exact"),
            Self::Prefix => f.write_str("prefix"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IndexType {
    Single(SingleIndex),
    Compound2((SingleIndex, SingleIndex)),
}

impl Display for IndexType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single(index) => Display::fmt(index, f),
            Self::Compound2((index_a, index_b)) => {
                Display::fmt(index_a, f)?;
                f.write_str(":")?;
                Display::fmt(index_b, f)?;
                Ok(())
            }
        }
    }
}

#[derive(Debug, Error, Diagnostic)]
pub enum ReadConversionError {
    #[error("Missing attribute: {0}")]
    NoSuchAttribute(String),
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    #[error("Failed to convert attribute: {0} from Plaintext")]
    ConversionFailed(String),
}

#[derive(Debug, Error)]
pub enum WriteConversionError {
    #[error("Failed to convert attribute: '{0}' to Plaintext")]
    ConversionFailed(String),
}

#[derive(Error, Debug)]
pub enum PrimaryKeyError {
    #[error("EncryptionError: {0}")]
    EncryptionError(#[from] EncryptionError),
    #[error("PrimaryKeyError: {0}")]
    Unknown(String),
}

pub trait Identifiable {
    type PrimaryKey: PrimaryKey;

    fn get_primary_key(&self) -> Self::PrimaryKey;

    fn is_sk_encrypted() -> bool {
        false
    }

    fn is_pk_encrypted() -> bool {
        false
    }

    fn type_name() -> Cow<'static, str>;
    fn sort_key_prefix() -> Option<Cow<'static, str>>;
}

pub trait Encryptable: Debug + Sized + Identifiable {
    /// Defines what attributes are protected and should be encrypted for this type.
    ///
    /// Must be equal to or a superset of protected_attributes on the [`Decryptable`] type.
    fn protected_attributes() -> Cow<'static, [Cow<'static, str>]>;

    /// Defines what attributes are plaintext for this type.
    ///
    /// Must be equal to or a superset of plaintext_attributes on the [`Decryptable`] type.
    fn plaintext_attributes() -> Cow<'static, [Cow<'static, str>]>;

    fn into_unsealed(self) -> Unsealed;
}

pub trait Searchable: Encryptable {
    fn attribute_for_index(
        &self,
        _index_name: &str,
        _index_type: IndexType,
    ) -> Option<ComposablePlaintext> {
        None
    }

    // TODO: Make a type to represent the result of this function
    /// Returns of indexes with their name and type.
    fn protected_indexes() -> Cow<'static, [(Cow<'static, str>, IndexType)]> {
        Cow::Borrowed(&[])
    }

    fn index_by_name(
        _index_name: &str,
        _index_type: IndexType,
    ) -> Option<Box<dyn ComposableIndex + Send>> {
        None
    }
}

pub trait Decryptable: Sized {
    /// Convert an `Unsealed` into a `Self`.
    fn from_unsealed(unsealed: Unsealed) -> Result<Self, SealError>;

    /// Defines what attributes are protected and decryptable for this type.
    ///
    /// Must be equal to or a subset of protected_attributes on the [`Encryptable`] type.
    fn protected_attributes() -> Cow<'static, [Cow<'static, str>]>;

    /// Defines what attributes are plaintext for this type.
    ///
    /// Must be equal to or a subset of protected_attributes on the [`Encryptable`] type.
    fn plaintext_attributes() -> Cow<'static, [Cow<'static, str>]>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherstash_client::encryption::TypeParseError;
    use std::collections::BTreeMap;

    fn make_btree_map() -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        map.insert("a".to_string(), "value-a".to_string());
        map.insert("b".to_string(), "value-b".to_string());
        map.insert("c".to_string(), "value-c".to_string());
        map
    }

    #[derive(Debug, Clone, PartialEq)]
    struct Test {
        pub pk: String,
        pub sk: String,
        pub name: String,
        pub age: i16,
        pub tag: String,
        pub attrs: BTreeMap<String, String>,
    }

    impl Identifiable for Test {
        type PrimaryKey = PkSk;
        fn get_primary_key(&self) -> Self::PrimaryKey {
            PkSk(self.pk.to_string(), self.sk.to_string())
        }
        #[inline]
        fn type_name() -> Cow<'static, str> {
            std::borrow::Cow::Borrowed("test")
        }
        #[inline]
        fn sort_key_prefix() -> Option<Cow<'static, str>> {
            None
        }
        fn is_pk_encrypted() -> bool {
            true
        }
        fn is_sk_encrypted() -> bool {
            false
        }
    }

    // TODO: Make this function consume and return the Unsealed
    fn put_attrs(unsealed: &mut Unsealed, attrs: BTreeMap<String, String>) {
        attrs.into_iter().for_each(|(k, v)| {
            unsealed.add_protected(format!("attrs.{k}"), Plaintext::from(v));
        })
    }

    impl Encryptable for Test {
        fn protected_attributes() -> Cow<'static, [Cow<'static, str>]> {
            Cow::Borrowed(&[Cow::Borrowed("name")])
        }

        fn plaintext_attributes() -> Cow<'static, [Cow<'static, str>]> {
            Cow::Borrowed(&[Cow::Borrowed("age")])
        }

        fn into_unsealed(self) -> Unsealed {
            // FIXME: This should be a "consuming" method
            let mut unsealed = Unsealed::new_with_descriptor(<Self as Identifiable>::type_name());
            unsealed.add_protected("name", Plaintext::from(self.name));
            unsealed.add_protected("age", Plaintext::from(self.age));
            unsealed.add_unprotected("tag", TableAttribute::from(self.tag));
            put_attrs(&mut unsealed, self.attrs);
            unsealed
        }
    }

    // TODO: Make this return an error that we we can expose to users
    fn get_attrs<T>(unsealed: &mut Unsealed) -> Result<T, SealError>
    where
        T: FromIterator<(String, String)>,
    {
        unsealed
            .take_protected_map("attrs")
            .ok_or(SealError::MissingAttribute("attrs".to_string()))?
            .into_iter()
            .map(|(k, v)| {
                TryFromPlaintext::try_from_plaintext(v)
                    .map(|v| (k, v))
                    .map_err(SealError::from)
            })
            .collect()
    }

    impl Decryptable for Test {
        fn from_unsealed(mut unsealed: Unsealed) -> Result<Self, SealError> {
            Ok(Self {
                // FIXME: How do we handle pk and sk? - especialy if they are encryptedl
                pk: String::from("pk"),
                sk: TryFromTableAttr::try_from_table_attr(unsealed.get_plaintext("sk"))?,
                name: TryFromPlaintext::try_from_optional_plaintext(
                    unsealed.take_protected("name"),
                )?,
                age: TryFromPlaintext::try_from_optional_plaintext(unsealed.take_protected("age"))?,
                tag: TryFromTableAttr::try_from_table_attr(unsealed.get_plaintext("tag"))?,
                attrs: get_attrs(&mut unsealed)?,
            })
        }

        // FIXME: create a card: this API is brittle because this function must match the from_unsealed function behavior
        // The same is true between this and the Encryptable trait
        fn protected_attributes() -> Cow<'static, [Cow<'static, str>]> {
            Cow::Borrowed(&[
                Cow::Borrowed("name"),
                Cow::Borrowed("age"),
                Cow::Borrowed("attrs"),
            ])
        }

        fn plaintext_attributes() -> Cow<'static, [Cow<'static, str>]> {
            Cow::Borrowed(&[Cow::Borrowed("tag")])
        }
    }

    #[test]
    fn test_encryptable() {
        let test = Test {
            pk: "pk".to_string(),
            sk: "sk".to_string(),
            name: "name".to_string(),
            tag: "tag".to_string(),
            age: 42,
            attrs: make_btree_map(),
        };

        let unsealed = test.clone().into_unsealed();
        assert_eq!(test, Test::from_unsealed(unsealed).unwrap());
    }
}
