use super::{
    attrs::{FlattenedEncryptedAttributes, FlattenedProtectedAttributes}, b64_encode, format_term_key, hmac, SealError,
    SealedTableEntry, Unsealed, MAX_TERMS_PER_INDEX,
};
use crate::{
    encrypted_table::{Dynamo, TableAttribute, TableAttributes, TableEntry},
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
use core::num;
use std::{borrow::Cow, collections::HashMap, ops::Deref};

/// The combination of plaintext, index, name and index type for a particular field
pub type UnsealedIndex = (
    ComposablePlaintext,
    Box<dyn ComposableIndex + Send>,
    Cow<'static, str>,
    IndexType,
);

// FIXME: Remove this (only used for debugging)
#[derive(Debug)]
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

struct RecordsWithTerms<'a> {
    num_protected_attributes: usize,
    records: Vec<RecordWithTerms<'a>>,
}

impl<'a> RecordsWithTerms<'a> {
    fn new(records: Vec<RecordWithTerms<'a>>, num_protected_attributes: usize) -> Self {
        Self {
            num_protected_attributes,
            records,
        }
    }

    async fn encrypt(self,
        cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
    ) -> Result<Vec<Sealed>, SealError> {
        let mut pksks = Vec::with_capacity(self.records.len());
        let mut record_terms = Vec::with_capacity(self.records.len());
        let mut unprotecteds = Vec::with_capacity(self.records.len());
        let mut protected =
            FlattenedProtectedAttributes::new_with_capacity(self.records.len() * self.num_protected_attributes);

        for sealer_with_terms in self.records {
            let (pksk, terms, flattened_protected, unprotected) = sealer_with_terms.into_parts();

            pksks.push(pksk);
            record_terms.push(terms);
            unprotecteds.push(unprotected);
            protected.extend(flattened_protected.into_iter());
        }

        let encrypted = protected.encrypt_all(cipher, self.num_protected_attributes).await?;

        encrypted
            .into_iter()
            .zip_eq(unprotecteds.into_iter())
            .zip_eq(record_terms.into_iter())
            .zip_eq(pksks.into_iter())
            .map(|record| {
                let (enc_attrs, unprotecteds, terms, pksk) = flatten_tuple(record);
                enc_attrs
                    .denormalize()
                    .map(|protected_attrs| {
                        Sealed {
                            pk: pksk.pk,
                            sk: pksk.sk,
                            attributes: unprotecteds.merge(protected_attrs),
                            terms,
                        }
                    })
            })
            .collect()
    }

}

struct RecordWithTerms<'a> {
    pksk: PrimaryKeyParts,
    unsealed: Unsealed,
    // TODO: What if we move the terms into the unsealed struct - and then into the NormalizedProtectedAttributes?
    terms: Vec<Term>,
    // FIXME: Don't use a Vec here - too many copies
    protected_attributes: Vec<Cow<'a, str>>,
}

impl<'a> RecordWithTerms<'a> {
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
        cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
        term_length: usize,
    ) -> Result<RecordsWithTerms<'a>, SealError> {
        let protected_attributes = protected_attributes.as_ref();
        let num_protected_attributes = protected_attributes.len();

        records
            .into_iter()
            .map(|sealer| {
                let mut pk = sealer.pk;
                let mut sk = sealer.sk;

                if sealer.is_pk_encrypted {
                    pk = b64_encode(hmac(&pk, None, cipher)?);
                }

                if sealer.is_sk_encrypted {
                    sk = b64_encode(hmac(&sk, Some(pk.as_str()), cipher)?);
                }

                let type_name = &sealer.type_name;

                // Index name, type and term
                let terms: Vec<(Cow<'_, str>, IndexType, Vec<u8>)> = sealer
                    .unsealed_indexes
                    .into_iter()
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

                let terms = terms
                    .into_iter()
                    .enumerate()
                    .map(|(i, (index_name, index_type, value))| {
                        let sk = b64_encode(hmac(
                            &format_term_key(sk.as_str(), &index_name, index_type, i),
                            Some(pk.as_str()),
                            cipher,
                        )?);

                        Ok::<_, SealError>(Term { sk, value })
                    })
                    .collect::<Result<Vec<Term>, _>>()?;

                Ok(RecordWithTerms {
                    pksk: PrimaryKeyParts { pk, sk },
                    unsealed: sealer.unsealed,
                    terms,
                    protected_attributes: protected_attributes.to_vec(),
                })
            })
            .try_collect()
            .map(|records| RecordsWithTerms::new(records, num_protected_attributes))
    }

    
    pub(crate) async fn seal_all<'a>(
        records: impl IntoIterator<Item = Sealer>,
        protected_attributes: impl AsRef<[Cow<'a, str>]>,
        cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
        term_length: usize,
    ) -> Result<Vec<Sealed>, SealError> {
        Self::index_all_terms(records, protected_attributes, cipher, term_length)?
            .encrypt(cipher)
            .await
        /*let records = records.into_iter();
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

            for attr in protected_attributes.iter() {
                protected.extend(record.unsealed.remove_protected_with_descriptor(attr)?);
            }

            let terms: Vec<(Cow<'_, str>, IndexType, Vec<u8>)> = record
                .unsealed_indexes
                .into_iter()
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
                record.unsealed.unprotected().clone(),
                terms,
            ));
        }

        // Only encrypt if there are actually protected attributes
        if !protected_attributes.is_empty() {
            let encrypted = cipher
                .encrypt(protected.iter().map(|(a, b)| (a, b.as_str())))
                .await?;

            for (encrypted, (_, attributes, _)) in encrypted
                .chunks_exact(protected.len())
                .zip(table_entries.iter_mut())
            {
                for (enc, name) in encrypted.iter().zip(protected.iter()) {
                    let name: &str = name.1.deref();

                    println!("Inserting protected attribute: {}", name);

                    attributes.insert(
                        String::from(match name {
                            // TODO: Possibly reinstate or move this
                            //"pk" => "__pk",
                            //"sk" => "__sk",
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

            output.push(dbg!(Sealed {
                pk,
                sk,
                attributes,
                terms,
            }));
        }

        Ok(output)*/
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

// FIXME: Remove this (only used for debugging)
#[derive(Debug)]
struct Term {
    sk: String,
    value: Vec<u8>,
}

// FIXME: Remove this (only used for debugging)
#[derive(Debug)]
// FIXME: Shouldn't this type be in the sealed module?
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
        mut index_predicate: impl FnMut(&str, &TableAttribute) -> bool,
    ) -> (SealedTableEntry, Vec<SealedTableEntry>) {
        let root_attributes = self.attributes.normalize();

        let index_attributes: TableAttributes = root_attributes
            .clone()
            .into_iter()
            .filter(|(key, value)| index_predicate(key, value))
            .map(|(key, value)| (key.to_string(), value.clone()))
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

#[inline]
fn flatten_tuple<A, B, C, D>((((a, b), c), d): (((A, B), C), D)) -> (A, B, C, D) {
    (a, b, c, d)
}