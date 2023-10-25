use crate::errors::ConfigError;
use serde::{
    de::Deserialize,
    ser::{Serialize, Serializer},
};

/// Represents a (possibly fully qualified) table.
/// It is specified by an optional schema and a table name.
#[derive(Debug, Clone, Eq)]
pub struct TablePath(pub Option<String>, pub String);

impl TablePath {
    pub fn unqualified(relname: impl Into<String>) -> Self {
        Self(None, relname.into())
    }

    /// Qualify the path with the given schema
    /// Note that if `schemaname` is an empty string, it will be set to `None`.
    /// This is handy as Query ASTs often represent null schema as an empty string.
    pub fn qualified(schemaname: impl Into<String>, relname: impl Into<String>) -> Self {
        let schemaname: String = schemaname.into();
        if schemaname.is_empty() {
            Self(None, relname.into())
        } else {
            Self(Some(schemaname), relname.into())
        }
    }

    pub fn as_string(&self) -> String {
        match self {
            Self(None, field) => field.to_string(),
            Self(Some(relation), field) => format!("{}.{}", relation, field),
        }
    }
}

impl TryFrom<&str> for TablePath {
    type Error = ConfigError;

    fn try_from(path: &str) -> Result<Self, Self::Error> {
        let tokens: Vec<&str> = path.split('.').collect();

        match tokens.len() {
            0 => Err(ConfigError::InvalidPath(path.to_string())),
            1 => Ok(TablePath::unqualified(tokens[0])),
            2 => Ok(TablePath::qualified(tokens[0], tokens[1])),
            _ => Err(ConfigError::UnexpectedQualifier(
                tokens[0].to_string(),
                path.to_string(),
            )),
        }
    }
}

impl PartialEq for TablePath {
    fn eq(&self, other: &Self) -> bool {
        if self.1 != other.1 {
            return false;
        };
        let schema = self.0.as_ref().zip(other.0.as_ref());

        match schema {
            None => true,
            Some((a, b)) if a == b => true,
            _ => false,
        }
    }
}

impl PartialEq<&[String]> for TablePath {
    fn eq(&self, other: &&[String]) -> bool {
        match other.len() {
            0 => false,
            1 => self.1 == *other[0],
            2 => {
                self.0
                    .as_ref()
                    .map(|schema| *schema == other[0])
                    .unwrap_or(false)
                    && self.1 == *other[1]
            }
            _ => false,
        }
    }
}

impl Serialize for TablePath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_string())
    }
}

impl<'de> Deserialize<'de> for TablePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        TablePath::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel_from(path_str: &str) -> Result<TablePath, ConfigError> {
        TablePath::try_from(path_str)
    }

    fn check_equal(subject: &str, target: &str) -> Result<(), Box<dyn std::error::Error>> {
        let subject: TablePath = subject.try_into()?;
        let target: TablePath = target.try_into()?;
        assert_eq!(subject, target);

        Ok(())
    }

    #[test]
    fn unqualified() {
        assert!(matches!(
            TablePath::unqualified("users"),
            TablePath(None, str) if str == *"users"
        ))
    }

    #[test]
    fn qualified() {
        assert!(matches!(
            TablePath::qualified("public", "users"),
            TablePath(Some(schema), table) if table == *"users" && schema == *"public"
        ))
    }

    #[test]
    fn qualified_by_empty_schema() {
        // Actually unqualified 😎
        assert!(matches!(
            TablePath::qualified("", "users"),
            TablePath(None, table) if table == *"users"
        ))
    }

    #[test]
    fn test_from_conversion() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(rel_from("users")?, TablePath::unqualified("users"));
        assert_eq!(
            rel_from("public.users")?,
            TablePath::qualified("public", "users")
        );
        assert!(rel_from("foo.bar.wee").is_err());
        // TODO
        //assert!(matches!(rel_from("foo.f/d"), Err(_)));

        Ok(())
    }

    #[test]
    fn equivalence_exact() -> Result<(), Box<dyn std::error::Error>> {
        check_equal("users", "users")?;
        check_equal("public.users", "public.users")?;

        Ok(())
    }

    #[test]
    fn equivalence_partial_target() -> Result<(), Box<dyn std::error::Error>> {
        check_equal("public.users", "users")?;

        Ok(())
    }

    #[test]
    fn equivalence_partial_subject() -> Result<(), Box<dyn std::error::Error>> {
        check_equal("users", "public.users")?;

        Ok(())
    }

    #[test]
    fn equalivalence_slice() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(TablePath::unqualified("users"), &["users".to_string()][..]);
        assert_eq!(
            TablePath::qualified("public", "users"),
            &["users".to_string()][..]
        );
        assert_eq!(
            TablePath::qualified("public", "users"),
            &["public".to_string(), "users".to_string()][..]
        );
        assert_ne!(TablePath::unqualified("users"), &[][..]);
        assert_ne!(TablePath::unqualified("users"), &["foo".to_string()][..]);
        assert_ne!(
            TablePath::unqualified("users"),
            &["foo".to_string(), "users".to_string()][..]
        );
        assert_ne!(
            TablePath::qualified("public", "users"),
            &["foo".to_string(), "users".to_string()][..]
        );
        assert_ne!(
            TablePath::qualified("public", "users"),
            &["foo".to_string(), "public".to_string(), "users".to_string()][..]
        );

        Ok(())
    }
}
