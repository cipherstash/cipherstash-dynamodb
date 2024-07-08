pub struct PrimaryKeyParts {
    pub pk: String,
    pub sk: String,
}

pub trait PrimaryKey: private::Sealed {}

impl PrimaryKey for Pk {}
impl PrimaryKey for PkSk {}

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

// impl PrimaryKey for Pk
// where
//     <PrimaryKey::Model as Identifiable>::PrimaryKey = Pk,
// {
//     fn into_parts<I: Identifiable>(
//         self,
//         cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
//     ) -> Result<PrimaryKeyParts, EncryptionError> {
//         Ok(I::get_primary_key_parts_from_key(self, cipher))
//     }
// }
//
// impl PrimaryKey for PkSk {
//     fn into_parts<I: Identifiable>(
//         self,
//         cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
//     ) -> Result<PrimaryKeyParts, EncryptionError> {
//         Ok(I::get_primary_key_parts_from_key(self, cipher))
//     }
// }
