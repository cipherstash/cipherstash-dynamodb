#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operator {
    Lt,
    Lte,
    Eq,
    Gt,
    Gte,
    Like,
    ILike,
    Unsupported,
}

impl Operator {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Lt => "<",
            Self::Lte => "<=",
            Self::Eq => "=",
            Self::Gt => ">",
            Self::Gte => ">=",
            Self::Like => "~~",   //Note: This is PostgreSQL specific syntax.
            Self::ILike => "~~*", //Note: This PostgreSQL specific syntax.
            // TODO: Probably better to use an Error and handle errors in callers
            _ => "unsupported",
        }
    }
}

impl From<&str> for Operator {
    fn from(value: &str) -> Self {
        match value {
            "<" => Self::Lt,
            "<=" => Self::Lte,
            "=" => Self::Eq,
            ">" => Self::Gt,
            ">=" => Self::Gte,
            "~~" => Self::Like,
            "~~*" => Self::ILike,
            _ => Self::Unsupported,
        }
    }
}

impl From<String> for Operator {
    fn from(value: String) -> Self {
        value.as_str().into()
    }
}

impl From<Vec<String>> for Operator {
    fn from(value: Vec<String>) -> Self {
        if value.len() == 1 {
            value[0].to_string().into()
        } else {
            Self::Unsupported
        }
    }
}

impl std::fmt::Display for Operator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Lt => "<",
            Self::Lte => "<=",
            Self::Eq => "==",
            Self::Gt => ">",
            Self::Gte => ">=",
            Self::Like => "LIKE",
            Self::ILike => "ILIKE",
            Self::Unsupported => "Unsupported",
        };

        write!(f, "{text}")
    }
}
