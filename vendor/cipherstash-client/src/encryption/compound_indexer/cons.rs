use crate::encryption::Plaintext;

#[derive(Debug, PartialEq, Clone)]
pub struct ConsArg2(pub Plaintext, pub Plaintext);

#[derive(Debug, PartialEq, Clone)]
pub struct ConsArg3(pub Plaintext, pub ConsArg2);

#[derive(Debug, PartialEq, Clone)]
pub struct ConsArg4(pub Plaintext, pub ConsArg3);

impl ConsArg2 {
    pub fn new(a: impl Into<Plaintext>, b: impl Into<Plaintext>) -> Self {
        Self(b.into(), a.into())
    }

    pub fn head(&self) -> &Plaintext {
        &self.0
    }

    pub fn tail(&self) -> &Plaintext {
        &self.1
    }
}

impl ConsArg3 {
    pub fn new(a: impl Into<Plaintext>, b: impl Into<Plaintext>, c: impl Into<Plaintext>) -> Self {
        Self(c.into(), ConsArg2::new(a, b))
    }

    pub fn head(&self) -> &Plaintext {
        &self.0
    }

    pub fn tail(&self) -> &ConsArg2 {
        &self.1
    }
}

impl<A, B> From<(A, B)> for ConsArg2
where
    Plaintext: From<A>,
    Plaintext: From<B>,
{
    fn from((a, b): (A, B)) -> Self {
        ConsArg2::new(a, b)
    }
}

impl<A, B, C> From<(A, B, C)> for ConsArg3
where
    Plaintext: From<A>,
    Plaintext: From<B>,
    Plaintext: From<C>,
{
    fn from((a, b, c): (A, B, C)) -> Self {
        ConsArg3::new(a, b, c)
    }
}

// TODO: ConsArg4

#[cfg(test)]
mod tests {
    use crate::encryption::compound_indexer::cons::{ConsArg2, ConsArg3};

    #[test]
    fn test_into_cons2() {
        let x: (i32, &str) = (1, "hey");
        let y: ConsArg2 = x.into();

        assert_eq!(y, ConsArg2::new(1, "hey".to_string()));
    }

    #[test]
    fn test_into_cons3() {
        let x: (i32, &str, i16) = (1, "hey", 12);
        let y: ConsArg3 = x.into();

        assert_eq!(y, ConsArg3::new(1_i32, "hey".to_string(), 12_i16));
    }
}
