use quote::format_ident;

#[derive(Clone)]
pub(crate) enum IndexType {
    Single(String, String),
    Compound1 {
        name: String,
        index: (String, String),
    },
    Compound2 {
        name: String,
        index: ((String, String), (String, String)),
    },
    //Compound3 { name: String, index: ((String, String), (String, String), (String, String)) }
}

impl IndexType {
    pub(super) fn single(name: String, index_type: String) -> Self {
        IndexType::Single(name, index_type)
    }

    pub(super) fn and(self, field: String, index_type: String) -> Result<Self, syn::Error> {
        match self {
            IndexType::Single(_, _) => unimplemented!(),
            IndexType::Compound1 { name, index } => Ok(IndexType::Compound2 {
                name: name.to_string(),
                index: (index.clone(), (field, index_type)),
            }),
            // TODO
            /*IndexType::Compound2 { name, index } => {
                Ok(IndexType::Compound3 {
                    name: name.to_string(),
                    index: (index.0, index.1, (field, index_type)),
                })
            },*/
            IndexType::Compound2 { .. } => Err(syn::Error::new_spanned(
                field,
                "Cannot add more than 2 fields to a compound index",
            )),
        }
    }

    pub(crate) fn type_to_ident(index_type: &str) -> Result<syn::Ident, syn::Error> {
        match index_type {
            "exact" => Ok(format_ident!("ExactIndex")),
            "prefix" => Ok(format_ident!("PrefixIndex")),
            _ => Err(syn::Error::new_spanned(
                index_type,
                format!("Unsupported index type: {}", index_type),
            )),
        }
    }
}