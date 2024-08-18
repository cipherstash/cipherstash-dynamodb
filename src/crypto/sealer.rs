use super::{
    b64_encode, format_term_key, hmac, SealError, SealedTableEntry, Unsealed, MAX_TERMS_PER_INDEX,
};
use crate::{
    encrypted_table::{TableAttribute, TableEntry},
    traits::PrimaryKeyParts,
    IndexType,
};
use cipherstash_client::{
    credentials::{service_credentials::ServiceToken, Credentials},
    encryption::{
        compound_indexer::{ComposableIndex, ComposablePlaintext, CompoundIndex},
        Encryption, IndexTerm,
    },
};
use itertools::Itertools;
use std::{borrow::Cow, collections::HashMap, ops::Deref};

/// The combination of plaintext, index, name and index type for a particular field
pub type UnsealedIndex = (
    ComposablePlaintext,
    Box<dyn ComposableIndex>,
    Cow<'static, str>,
    IndexType,
);

/// Builder pattern for sealing a record of type, `T`.
pub struct Sealer {
    pub(crate) pk: String,
    pub(crate) sk: String,

    pub(crate) is_pk_encrypted: bool,
    pub(crate) is_sk_encrypted: bool,

    pub(crate) type_name: Cow<'static, str>,

    pub(crate) unsealed_indexes: Vec<UnsealedIndex>,

    pub(crate) unsealed: Unsealed,
}

struct Term {
    sk: String,
    value: Vec<u8>,
}

pub struct Sealed {
    pk: String,
    sk: String,
    attributes: HashMap<String, TableAttribute>,
    terms: Vec<Term>,
}

impl Sealed {
    pub fn len(&self) -> usize {
        // the length of the terms plus the root entry
        self.terms.len() + 1
    }

    pub fn primary_key(&self) -> PrimaryKeyParts {
        PrimaryKeyParts {
            pk: self.pk.clone(),
            sk: self.sk.clone(),
        }
    }

    pub fn into_table_entries(
        self,
        mut index_predicate: impl FnMut(&str, &TableAttribute) -> bool,
    ) -> (SealedTableEntry, Vec<SealedTableEntry>) {
        let root_attributes = self.attributes;

        let index_attributes = root_attributes
            .iter()
            .filter(|(key, value)| index_predicate(key, value))
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect::<HashMap<_, _>>();

        let term_entries = self
            .terms
            .into_iter()
            .map(|Term { sk, value }| {
                SealedTableEntry(TableEntry::new_with_attributes(
                    self.pk.clone(),
                    sk,
                    Some(value),
                    index_attributes.clone(),
                ))
            })
            .collect();

        (
            SealedTableEntry(TableEntry::new_with_attributes(
                self.pk,
                self.sk,
                None,
                root_attributes,
            )),
            term_entries,
        )
    }
}

impl Sealer {
    // pub fn new<T>(inner: T) -> Self {
    //     Self {
    //         inner,
    //         unsealed: Unsealed::new(),
    //     }
    // }

    // pub fn new_with_descriptor<T>(inner: T, descriptor: impl Into<String>) -> Self {
    //     Self {
    //         inner,
    //         unsealed: Unsealed::new_with_descriptor(descriptor),
    //     }
    // }

    // pub fn add_protected<F>(mut self, name: impl Into<String>, f: F) -> Result<Self, SealError>
    // where
    //     F: FnOnce(&T) -> Plaintext,
    // {
    //     let name: String = name.into();

    //     self.unsealed.add_protected(name, f(&self.inner));
    //     Ok(self)
    // }

    // pub fn add_plaintext<F>(mut self, name: impl Into<String>, f: F) -> Result<Self, SealError>
    // where
    //     F: FnOnce(&T) -> TableAttribute,
    // {
    //     let name: String = name.into();
    //     self.unsealed.add_unprotected(name, f(&self.inner));
    //     Ok(self)
    // }

    pub(crate) async fn seal_all<'a>(
        records: impl IntoIterator<Item = Sealer>,
        protected_attributes: impl AsRef<[Cow<'a, str>]>,
        cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
        term_length: usize,
    ) -> Result<Vec<Sealed>, SealError> {
        let records = records.into_iter();
        let records_len = records.size_hint().1.unwrap_or(1);

        let protected_attributes = protected_attributes.as_ref();

        let mut protected = Vec::with_capacity(records_len * protected_attributes.len());
        let mut table_entries = Vec::with_capacity(records_len);

        for mut record in records {
            let mut pk = record.pk;
            let mut sk = record.sk;

            if record.is_pk_encrypted {
                pk = b64_encode(hmac(&pk, None, cipher)?);
            }

            if record.is_sk_encrypted {
                sk = b64_encode(hmac(&sk, Some(pk.as_str()), cipher)?);
            }

            let type_name = &record.type_name;

            // let PrimaryKeyParts { pk, sk } = encrypt_primary_key::<S>(
            //     record.inner.get_primary_key(),
            //     &S::type_name(),
            //     S::sort_key_prefix().as_deref(),
            //     cipher,
            // )?;

            for attr in protected_attributes.iter() {
                protected.push(record.unsealed.remove_protected_with_descriptor(attr)?);
            }

            let terms: Vec<(Cow<'_, str>, IndexType, Vec<u8>)> = record
                .unsealed_indexes
                .into_iter()
                // .iter()
                // .map(|(index_name, index_type)| {
                //     record
                //         .inner
                //         .attribute_for_index(index_name, *index_type)
                //         .and_then(|attr| {
                //             S::index_by_name(index_name, *index_type)
                //                 .map(|index| (attr, index, index_name, index_type))
                //         })
                //         .ok_or(SealError::MissingAttribute(index_name.to_string()))
                .map(|(attr, index, index_name, index_type)| {
                    let term = cipher.compound_index(
                        &CompoundIndex::new(index),
                        attr,
                        Some(format!("{}#{}", type_name, index_name)),
                        term_length,
                    )?;

                    Ok::<_, SealError>((index_name, index_type, term))
                })
                .map(|index_term| match index_term {
                    Ok((index_name, index_type, IndexTerm::Binary(x))) => {
                        Ok(vec![(index_name, index_type, x)])
                    }
                    Ok((index_name, index_type, IndexTerm::BinaryVec(x))) => Ok(x
                        .into_iter()
                        .take(MAX_TERMS_PER_INDEX)
                        .map(|x| (index_name.clone(), index_type, x))
                        .collect()),
                    _ => Err(SealError::InvalidCiphertext("Invalid index term".into())),
                })
                .flatten_ok()
                .try_collect()?;

            table_entries.push((
                PrimaryKeyParts { pk, sk },
                record.unsealed.unprotected(),
                terms,
            ));
        }

        let encrypted = cipher
            .encrypt(protected.iter().map(|(a, b)| (a, b.as_str())))
            .await?;

        for (encrypted, (_, attributes, _)) in encrypted
            .chunks_exact(protected_attributes.len())
            .zip(table_entries.iter_mut())
        {
            for (enc, name) in encrypted.iter().zip(protected_attributes.iter()) {
                let name: &str = name.deref();

                attributes.insert(
                    String::from(match name {
                        "pk" => "__pk",
                        "sk" => "__sk",
                        _ => name,
                    }),
                    TableAttribute::Bytes(enc.to_vec().map_err(|_| {
                        SealError::InvalidCiphertext(
                            "Failed to serialize encrypted record as bytes".into(),
                        )
                    })?),
                );
            }
        }

        let mut output = Vec::with_capacity(table_entries.len());

        for (PrimaryKeyParts { pk, sk }, attributes, terms) in table_entries.into_iter() {
            let terms = terms
                .into_iter()
                .enumerate()
                .map(|(i, (index_name, index_type, term))| {
                    let sk = b64_encode(hmac(
                        &format_term_key(sk.as_str(), &index_name, index_type, i),
                        Some(pk.as_str()),
                        cipher,
                    )?);

                    Ok::<_, SealError>(Term { sk, value: term })
                })
                .collect::<Result<_, SealError>>()?;

            output.push(Sealed {
                pk,
                sk,
                attributes,
                terms,
            });
        }

        Ok(output)
    }

    pub(crate) async fn seal<'a>(
        self,
        protected_attributes: impl AsRef<[Cow<'a, str>]>,
        cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
        term_length: usize,
    ) -> Result<Sealed, SealError> {
        let mut vec = Self::seal_all([self], protected_attributes, cipher, term_length).await?;

        if vec.len() != 1 {
            let actual = vec.len();

            return Err(SealError::AssertionFailed(format!(
                "Expected seal_all to return 1 result but got {actual}"
            )));
        }

        Ok(vec.remove(0))
    }
}
