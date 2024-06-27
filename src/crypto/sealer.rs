use super::{b64_encode, format_term_key, hmac, SealError, Sealed, Unsealed, MAX_TERMS_PER_INDEX};
use crate::{
    encrypted_table::{TableAttribute, TableEntry},
    traits::PrimaryKeyParts,
    IndexType, Searchable,
};
use cipherstash_client::{
    credentials::{service_credentials::ServiceToken, Credentials},
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

    pub(crate) async fn seal_all<S: Searchable>(
        records: impl AsRef<[Sealer<S>]>,
        cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
        term_length: usize,
    ) -> Result<Vec<(PrimaryKeyParts, Vec<Sealed>)>, SealError> {
        let records = records.as_ref();
        let protected_attributes = S::protected_attributes();
        let protected_indexes = S::protected_indexes();

        let mut protected = Vec::with_capacity(records.len() * protected_attributes.len());
        let mut table_entries = Vec::with_capacity(records.len());

        for record in records.iter() {
            let mut pk = record.inner.partition_key();
            let mut sk = record.inner.sort_key();

            if S::is_partition_key_encrypted() {
                pk = b64_encode(hmac(&pk, None, cipher)?);
            }

            if S::is_sort_key_encrypted() {
                sk = b64_encode(hmac(&sk, Some(pk.as_str()), cipher)?);
            }

            for attr in protected_attributes.iter() {
                protected.push(record.unsealed.protected_with_descriptor(attr)?);
            }

            let table_entry = TableEntry::new_with_attributes(
                pk.clone(),
                sk.clone(),
                None,
                record.unsealed.unprotected(),
            );

            let terms: Vec<(&&str, IndexType, Vec<u8>)> = protected_indexes
                .iter()
                .map(|(index_name, index_type)| {
                    record
                        .inner
                        .attribute_for_index(index_name, *index_type)
                        .and_then(|attr| {
                            S::index_by_name(index_name, *index_type)
                                .map(|index| (attr, index, index_name, index_type))
                        })
                        .ok_or(SealError::MissingAttribute(index_name.to_string()))
                        .and_then(|(attr, index, index_name, index_type)| {
                            let term = cipher.compound_index(
                                &CompoundIndex::new(index),
                                attr,
                                Some(format!("{}#{}", S::type_name(), index_name)),
                                term_length,
                            )?;

                            Ok::<_, SealError>((index_name, index_type, term))
                        })
                })
                .map(|index_term| match index_term {
                    Ok((index_name, index_type, IndexTerm::Binary(x))) => {
                        Ok(vec![(index_name, *index_type, x)])
                    }
                    Ok((index_name, index_type, IndexTerm::BinaryVec(x))) => Ok(x
                        .into_iter()
                        .take(MAX_TERMS_PER_INDEX)
                        .map(|x| (index_name, *index_type, x))
                        .collect()),
                    _ => Err(SealError::InvalidCiphertext("Invalid index term".into())),
                })
                .flatten_ok()
                .try_collect()?;

            table_entries.push((PrimaryKeyParts { pk, sk }, table_entry, terms));
        }

        let encrypted = cipher.encrypt(protected).await?;

        for (encrypted, (_, table_entry, _)) in encrypted
            .chunks_exact(protected_attributes.len())
            .zip(table_entries.iter_mut())
        {
            for (enc, name) in encrypted.iter().zip(protected_attributes.iter()) {
                table_entry.add_attribute(
                    match *name {
                        "pk" => "__pk",
                        "sk" => "__sk",
                        _ => name,
                    },
                    TableAttribute::Bytes(enc.to_vec().map_err(|_| {
                        SealError::InvalidCiphertext(
                            "Failed to serialize encrypted record as bytes".into(),
                        )
                    })?),
                );
            }
        }

        let mut output = Vec::with_capacity(records.len());

        for (primary_key, table_entry, terms) in table_entries.into_iter() {
            let table_entries = terms
                .into_iter()
                .enumerate()
                .map(|(i, (index_name, index_type, term))| {
                    Ok(Sealed(table_entry.clone().set_term(term).set_sk(
                        b64_encode(hmac(
                            &format_term_key(&primary_key.sk, index_name, index_type, i),
                            Some(primary_key.pk.as_str()),
                            cipher,
                        )?),
                    )))
                })
                .chain(once(Ok(Sealed(table_entry.clone()))))
                .collect::<Result<_, SealError>>()?;

            output.push((primary_key, table_entries));
        }

        Ok(output)
    }

    pub(crate) async fn seal<C>(
        self,
        cipher: &Encryption<C>,
        term_length: usize,
    ) -> Result<(PrimaryKeyParts, Vec<Sealed>), SealError>
    where
        C: Credentials<Token = ServiceToken>,
        T: Searchable,
    {
        let mut vec = Self::seal_all([self], cipher, term_length).await?;

        if vec.len() != 1 {
            let actual = vec.len();

            return Err(SealError::AssertionFailed(format!(
                "Expected seal_all to return 1 result but got {actual}"
            )));
        }

        Ok(vec.remove(0))
    }
}
