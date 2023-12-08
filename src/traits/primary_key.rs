use crate::Encryptable;

pub struct PrimaryKeyParts {
    pub pk: String,
    pub sk: String,
}

pub trait PrimaryKey: private::Sealed {
    fn into_parts<E: Encryptable>(self) -> PrimaryKeyParts;
}

pub struct Pk(String);

impl Pk {
    pub fn new(pk: impl Into<String>) -> Self {
        Self(pk.into())
    }
}

impl<P: Into<String>> From<P> for Pk {
    fn from(value: P) -> Self {
        Self::new(value)
    }
}

pub struct PkSk(String, String);

impl<Pk: Into<String>, Sk: Into<String>> From<(Pk, Sk)> for PkSk {
    fn from(value: (Pk, Sk)) -> Self {
        Self::new(value.0, value.1)
    }
}

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
    fn into_parts<E: Encryptable>(self) -> PrimaryKeyParts {
        PrimaryKeyParts {
            pk: self.0,
            sk: E::sort_key_prefix().unwrap_or(E::type_name()).to_string(),
        }
    }
}

impl PrimaryKey for PkSk {
    fn into_parts<E: Encryptable>(self) -> PrimaryKeyParts {
        let sk = self.1;

        PrimaryKeyParts {
            pk: self.0,
            sk: E::sort_key_prefix()
                .map(|x| format!("{x}#{sk}"))
                .unwrap_or_else(|| sk.to_string()),
        }
    }
}
