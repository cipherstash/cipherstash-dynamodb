pub struct PrimaryKeyParts {
    pub pk: String,
    pub sk: String,
}

pub trait PrimaryKey: private::Sealed {
    type Pk;
    type Sk;

    fn into_parts(
        self,
        type_name: &'static str,
        sort_key_prefix: Option<&'static str>,
    ) -> PrimaryKeyParts;
}

impl PrimaryKey for Pk {
    type Pk = String;
    type Sk = ();

    fn into_parts(
        self,
        type_name: &'static str,
        _sort_key_prefix: Option<&'static str>,
    ) -> PrimaryKeyParts {
        PrimaryKeyParts {
            pk: self.0,
            sk: type_name.into(),
        }
    }
}

impl PrimaryKey for PkSk {
    type Pk = String;
    type Sk = String;

    fn into_parts(
        self,
        _type_name: &'static str,
        sort_key_prefix: Option<&'static str>,
    ) -> PrimaryKeyParts {
        PrimaryKeyParts {
            pk: self.0,
            sk: if let Some(prefix) = sort_key_prefix {
                format!("{prefix}#{}", self.1)
            } else {
                self.1
            },
        }
    }
}

pub struct Pk(pub String);

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

pub struct PkSk(pub String, pub String);

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
