use super::{
    attrs::FlattenedProtectedAttributes, b64_encode, format_term_key, SealError, SealedTableEntry,
    Unsealed, MAX_TERMS_PER_INDEX,
};
use crate::{
    encrypted_table::{
        AttributeName, ScopedZeroKmsCipher, TableAttribute, TableAttributes, TableEntry,
    },
    traits::PrimaryKeyParts,
    IndexType,
};
use cipherstash_client::encryption::{
    compound_indexer::{ComposableIndex, ComposablePlaintext},
    IndexTerm,
};
use itertools::Itertools;
use std::{borrow::Cow, collections::HashMap};

/// The combination of plaintext, index, name and index type for a particular field
pub type UnsealedIndex = (
    ComposablePlaintext,
    Box<dyn ComposableIndex + Send>,
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

struct RecordsWithTerms {
    num_protected_attributes: usize,
    records: Vec<RecordWithTerms>,
}

impl RecordsWithTerms {
    fn new(records: Vec<RecordWithTerms>, num_protected_attributes: usize) -> Self {
        Self {
            num_protected_attributes,
            records,
        }
    }

    async fn encrypt(self, cipher: &ScopedZeroKmsCipher) -> Result<Vec<Sealed>, SealError> {
        let num_records = self.records.len();
        let mut pksks = Vec::with_capacity(num_records);
        let mut record_terms = Vec::with_capacity(num_records);
        let mut unprotecteds = Vec::with_capacity(num_records);
        let mut protected = FlattenedProtectedAttributes::new_with_capacity(
            num_records * self.num_protected_attributes,
        );

        for sealer_with_terms in self.records {
            let (pksk, terms, flattened_protected, unprotected) = sealer_with_terms.into_parts();

            pksks.push(pksk);
            record_terms.push(terms);
            unprotecteds.push(unprotected);
            protected.extend(flattened_protected.into_iter());
        }

        // TODO: Split this out into separate functions and/or implement From for the tuple into Sealed
        if protected.is_empty() {
            unprotecteds
                .into_iter()
                .zip_eq(record_terms.into_iter())
                .zip_eq(pksks.into_iter())
                .map(|record| {
                    let (attributes, terms, pksk) = flatten_tuple_3(record);
                    Ok(Sealed {
                        pk: pksk.pk,
                        sk: pksk.sk,
                        attributes,
                        terms,
                    })
                })
                .collect()
        } else {
            let encrypted = protected.encrypt_all(cipher, num_records).await?;

            encrypted
                .into_iter()
                .zip_eq(unprotecteds.into_iter())
                .zip_eq(record_terms.into_iter())
                .zip_eq(pksks.into_iter())
                .map(|record| {
                    let (enc_attrs, unprotecteds, terms, pksk) = flatten_tuple_4(record);
                    enc_attrs.denormalize().map(|protected_attrs| Sealed {
                        pk: pksk.pk,
                        sk: pksk.sk,
                        attributes: unprotecteds.merge(protected_attrs),
                        terms,
                    })
                })
                .collect()
        }
    }
}

struct RecordWithTerms {
    pksk: PrimaryKeyParts,
    unsealed: Unsealed,
    terms: Vec<Term>,
}

impl RecordWithTerms {
    fn into_parts(
        self,
    ) -> (
        PrimaryKeyParts,
        Vec<Term>,
        FlattenedProtectedAttributes,
        TableAttributes,
    ) {
        let (flattened_protected, unprotected) = self.unsealed.flatten_into_parts();
        (self.pksk, self.terms, flattened_protected, unprotected)
    }
}

impl Sealer {
    fn index_all_terms<'a>(
        records: impl IntoIterator<Item = Sealer>,
        protected_attributes: impl AsRef<[Cow<'a, str>]>,
        cipher: &ScopedZeroKmsCipher,
    ) -> Result<RecordsWithTerms, SealError> {
        let protected_attributes = protected_attributes.as_ref();
        let num_protected_attributes = protected_attributes.len();

        records
            .into_iter()
            .map(|sealer| {
                let mut pk = sealer.pk;
                let mut sk = sealer.sk;

                // TODO: Use the same method as Get (encrypt_primary_key_parts)
                if sealer.is_pk_encrypted {
                    pk = b64_encode(cipher.mac::<32>(&pk, None));
                }

                if sealer.is_sk_encrypted {
                    sk = b64_encode(cipher.mac::<32>(&sk, Some(pk.as_str())));
                }

                let type_name = &sealer.type_name;

                // Index name, type and term
                let terms: Vec<(Cow<'_, str>, IndexType, Vec<u8>)> = sealer
                    .unsealed_indexes
                    .into_iter()
                    .map(|(attr, index, index_name, index_type)| {
                        let info = format!("{}#{}", type_name, index_name);
                        let term = cipher.compound_index(index, attr, info)?;

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
                        x => Err(SealError::InvalidCiphertext(format!(
                            "Invalid index term: `{x:?}"
                        ))),
                    })
                    .flatten_ok()
                    .try_collect()?;

                let terms = terms
                    .into_iter()
                    .enumerate()
                    .map(|(i, (index_name, index_type, value))| {
                        let sk = b64_encode(cipher.mac::<32>(
                            &format_term_key(sk.as_str(), &index_name, index_type, i),
                            Some(pk.as_str()),
                        ));

                        Ok::<_, SealError>(Term { sk, value })
                    })
                    .collect::<Result<Vec<Term>, _>>()?;

                Ok(RecordWithTerms {
                    pksk: PrimaryKeyParts { pk, sk },
                    unsealed: sealer.unsealed,
                    terms,
                })
            })
            .try_collect()
            .map(|records| RecordsWithTerms::new(records, num_protected_attributes))
    }

    pub(crate) async fn seal_all<'a>(
        records: impl IntoIterator<Item = Sealer>,
        protected_attributes: impl AsRef<[Cow<'a, str>]>,
        cipher: &ScopedZeroKmsCipher,
    ) -> Result<Vec<Sealed>, SealError> {
        Self::index_all_terms(records, protected_attributes, cipher)?
            .encrypt(cipher)
            .await
    }

    pub(crate) async fn seal<'a>(
        self,
        protected_attributes: impl AsRef<[Cow<'a, str>]>,
        cipher: &ScopedZeroKmsCipher,
    ) -> Result<Sealed, SealError> {
        let mut vec = Self::seal_all([self], protected_attributes, cipher).await?;

        if vec.len() != 1 {
            let actual = vec.len();

            return Err(SealError::AssertionFailed(format!(
                "Expected seal_all to return 1 result but got {actual}"
            )));
        }

        Ok(vec.remove(0))
    }
}

#[derive(Debug)]
struct Term {
    sk: String,
    value: Vec<u8>,
}

// FIXME: This struct is almost _identical_ to the one in encrypted_table/table_entry.rs
pub struct Sealed {
    pk: String,
    sk: String,
    attributes: TableAttributes,
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

    /// Returns the root entry and the term entries for this record.
    /// `index_predicate` is used to... TODO!!!.
    pub fn into_table_entries(
        self,
        mut index_predicate: impl FnMut(&AttributeName, &TableAttribute) -> bool,
    ) -> (SealedTableEntry, Vec<SealedTableEntry>) {
        let root_attributes = self.attributes;

        let index_attributes: TableAttributes = root_attributes
            .clone()
            .into_iter()
            .filter(|(name, value)| index_predicate(name, value))
            .map(|(name, value)| (name, value.clone()))
            .collect::<HashMap<_, _>>()
            .into();

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

// TODO: Move these somewhere else
#[inline]
fn flatten_tuple_4<A, B, C, D>((((a, b), c), d): (((A, B), C), D)) -> (A, B, C, D) {
    (a, b, c, d)
}

#[inline]
fn flatten_tuple_3<A, B, C>(((a, b), c): ((A, B), C)) -> (A, B, C) {
    (a, b, c)
}
