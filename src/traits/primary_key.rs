pub struct PrimaryKeyParts {
    pub(crate) pk: String,
    pub(crate) sk: String,
}

pub trait PrimaryKey: private::Sealed {
    fn into_parts(self, sk_prefix: &str) -> PrimaryKeyParts;
}

pub struct Pk(String);

impl Pk {
    pub fn new(pk: impl Into<String>) -> Self {
        Self(pk.into())
    }
}

impl From<String> for Pk {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Pk {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

pub struct PkSk(String, String);

impl PkSk {
    pub fn new(pk: impl Into<String>, sk: impl Into<String>) -> Self {
        Self(pk.into(), sk.into())
    }
}

mod private {
    use super::*;

    pub trait Sealed {}

    impl Sealed for Pk {}
    impl Sealed for PkSk {}
}

impl PrimaryKey for Pk {
    fn into_parts(self, sk_prefix: &str) -> PrimaryKeyParts {
        PrimaryKeyParts {
            pk: self.0,
            sk: sk_prefix.to_string(),
        }
    }
}

impl PrimaryKey for PkSk {
    fn into_parts(self, sk_prefix: &str) -> PrimaryKeyParts {
        PrimaryKeyParts {
            pk: self.0,
            sk: format!("{}#{}", sk_prefix, self.1),
        }
    }
}
