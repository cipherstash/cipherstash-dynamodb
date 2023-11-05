use super::{encrypt_partition_key, SealError, Sealed, Unsealed, MAX_TERMS_PER_INDEX};
use crate::{
    encrypted_table::{TableAttribute, TableEntry},
    SearchableRecord,
};
use cipherstash_client::{
    credentials::{vitur_credentials::ViturToken, Credentials},
    encryption::{compound_indexer::CompoundIndex, Encryption, IndexTerm, Plaintext},
};
use itertools::Itertools;
use std::iter::once;

/// Builder pattern for sealing a record of type, `T`.
pub struct Sealer<T> {
    inner: T,
    unsealed: Unsealed,
}

impl<T> Sealer<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            unsealed: Unsealed::new(),
        }
    }

    pub fn new_with_descriptor(inner: T, descriptor: impl Into<String>) -> Self {
        Self {
            inner,
            unsealed: Unsealed::new_with_descriptor(descriptor),
        }
    }

    pub fn add_protected<F>(mut self, name: impl Into<String>, f: F) -> Result<Self, SealError>
    where
        F: FnOnce(&T) -> Plaintext,
    {
        let name: String = name.into();

        self.unsealed.add_protected(name, f(&self.inner));
        Ok(self)
    }

    pub fn add_plaintext<F>(mut self, name: impl Into<String>, f: F) -> Result<Self, SealError>
    where
        F: FnOnce(&T) -> TableAttribute,
    {
        let name: String = name.into();
        self.unsealed.add_unprotected(name, f(&self.inner));
        Ok(self)
    }

    pub(crate) async fn seal<C>(
        self,
        cipher: &Encryption<C>,
        term_length: usize, // TODO: SealError
    ) -> Result<(String, Vec<Sealed>), SealError>
    where
        C: Credentials<Token = ViturToken>,
        T: SearchableRecord,
    {
        let pk = encrypt_partition_key(&self.inner.partition_key(), cipher).unwrap(); // FIXME

        let mut table_entry = TableEntry::new_with_attributes(
            pk.clone(),
            T::type_name().to_string(),
            None,
            self.unsealed.unprotected(),
        );

        let protected = T::protected_attributes()
            .iter()
            .map(|name| self.unsealed.protected_with_descriptor(name))
            .collect::<Result<Vec<(&Plaintext, &str)>, _>>()?;

        cipher
            .encrypt(protected)
            .await?
            .into_iter()
            .zip(T::protected_attributes().into_iter())
            .for_each(|(enc, name)| {
                if let Some(e) = enc {
                    table_entry.add_attribute(name, e.into());
                }
            });

        let protected_indexes = T::protected_indexes();
        let terms: Vec<(&&str, Vec<u8>)> = protected_indexes
            .iter()
            .map(|index_name| {
                self.inner
                    .attribute_for_index(index_name)
                    .and_then(|attr| {
                        T::index_by_name(index_name).map(|index| (attr, index, index_name))
                    })
                    .ok_or(SealError::MissingAttribute(index_name.to_string()))
                    .and_then(|(attr, index, index_name)| {
                        cipher
                            .compound_index(
                                &CompoundIndex::new(index),
                                attr,
                                Some(format!("{}#{}", T::type_name(), index_name)),
                                term_length,
                            )
                            .map_err(SealError::CryptoError)
                            .and_then(|index_term| match index_term {
                                IndexTerm::Binary(x) => Ok(vec![(index_name, x)]),
                                IndexTerm::BinaryVec(x) => {
                                    Ok(x.into_iter().map(|x| (index_name, x)).collect())
                                }
                                _ => Err(SealError::InvalidCiphertext("Invalid index term".into())),
                            })
                    })
            })
            .flatten_ok()
            .try_collect()?;

        let table_entries = terms
            .into_iter()
            .enumerate()
            .take(MAX_TERMS_PER_INDEX)
            .map(|(i, (index_name, term))| {
                Sealed(
                    table_entry
                        .clone()
                        .set_term(hex::encode(term))
                        // TODO: HMAC the sort key, too (users#index_name#pk)
                        .set_sk(format!("{}#{}#{}", T::type_name(), index_name, i)),
                )
            })
            .chain(once(Sealed(table_entry.clone())))
            .collect();

        Ok((pk, table_entries))
    }

    #[allow(dead_code)]
    fn seal_iter<I>(_iter: I) -> Vec<Sealed>
    where
        I: IntoIterator<Item = Self>,
    {
        unimplemented!()
    }
}
