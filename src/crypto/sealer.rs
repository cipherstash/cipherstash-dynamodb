use super::{b64_encode, format_term_key, hmac, SealError, Sealed, Unsealed, MAX_TERMS_PER_INDEX};
use crate::{
    encrypted_table::TableEntry,
    traits::{PrimaryKeyParts, TableAttribute},
    Encryptable, IndexType, Searchable,
};
use cipherstash_client::{
    credentials::{service_credentials::ServiceToken, Credentials},
    encryption::{
        compound_indexer::{ComposableIndex, ComposablePlaintext, CompoundIndex},
        Encryption, IndexTerm, Plaintext,
    },
};
use itertools::Itertools;
use std::iter::once;

const TERM_LENGTH: usize = 12;

pub struct Sealer<'p, 'e, C>
where
    C: Credentials<Token = ServiceToken>,
{
    table_entries: Vec<(
        PrimaryKeyParts,
        TableEntry,
        Vec<(&'static str, IndexType, Vec<u8>)>,
    )>,
    protected: Vec<(&'p Plaintext, &'p str)>,
    cipher: &'e Encryption<C>,

    is_partition_key_encrypted: bool,
    is_sort_key_encrypted: bool,
    index_by_name: fn(&str, IndexType) -> Option<Box<dyn ComposableIndex>>,
    protected_attributes: &'static [&'static str],
    protected_indexes: &'static [(&'static str, IndexType)],
    type_name: &'static str,
}

impl<'p, 'e, C> Sealer<'p, 'e, C>
where
    C: Credentials<Token = ServiceToken>,
{
    pub fn new(
        cipher: &'e Encryption<C>,
        is_partition_key_encrypted: bool,
        is_sort_key_encrypted: bool,
        index_by_name: fn(&str, IndexType) -> Option<Box<dyn ComposableIndex>>,
        protected_attributes: &'static [&'static str],
        protected_indexes: &'static [(&'static str, IndexType)],
        type_name: &'static str,
    ) -> Self {
        Self {
            table_entries: Vec::new(),
            protected: Vec::new(),
            cipher,

            is_partition_key_encrypted,
            is_sort_key_encrypted,
            index_by_name,
            protected_attributes,
            protected_indexes,
            type_name,
        }
    }

    /// Reserve space for n additional unsealed records
    pub fn reserve(&mut self, n_records: usize) {
        self.protected
            .reserve(n_records * self.protected_attributes.len());
        self.table_entries.reserve(n_records);
    }

    pub fn push<I>(
        &mut self,
        unsealed: &'p Unsealed,
        partition_key: String,
        sort_key: String,
        attributes_for_indexes: I,
    ) -> Result<(), SealError>
    where
        I: IntoIterator<Item = ComposablePlaintext>,
    {
        let pk = if self.is_partition_key_encrypted {
            b64_encode(hmac(&partition_key, None, self.cipher)?)
        } else {
            partition_key
        };

        let sk = if self.is_sort_key_encrypted {
            b64_encode(hmac(&sort_key, Some(pk.as_str()), self.cipher)?)
        } else {
            sort_key
        };

        for &attr in self.protected_attributes.iter() {
            self.protected
                .push(unsealed.protected_with_descriptor(attr)?);
        }

        let table_entry =
            TableEntry::new_with_attributes(pk.clone(), sk.clone(), None, unsealed.unprotected());

        let terms: Vec<(&str, IndexType, Vec<u8>)> = self
            .protected_indexes
            .iter()
            .zip(attributes_for_indexes)
            .map(|(&(index_name, index_type), attr)| {
                let index = ((self.index_by_name)(index_name, index_type))
                    .ok_or(SealError::MissingAttribute(index_name.to_string()))?;
                let index_term = self.cipher.compound_index(
                    &CompoundIndex::new(index),
                    attr,
                    Some(format!("{}#{}", self.type_name, index_name)),
                    TERM_LENGTH,
                )?;

                match index_term {
                    IndexTerm::Binary(x) => Ok(vec![(index_name, index_type, x)]),
                    IndexTerm::BinaryVec(x) => Ok(x
                        .into_iter()
                        .take(MAX_TERMS_PER_INDEX)
                        .map(|x| (index_name, index_type, x))
                        .collect()),
                    _ => Err(SealError::InvalidCiphertext("Invalid index term".into())),
                }
            })
            .flatten_ok()
            .try_collect()?;

        self.table_entries
            .push((PrimaryKeyParts { pk, sk }, table_entry, terms));

        Ok(())
    }

    pub async fn finalize(mut self) -> Result<Vec<(PrimaryKeyParts, Vec<Sealed>)>, SealError> {
        let encrypted = self.cipher.encrypt(self.protected).await?;

        for (encrypted, (_, table_entry, _)) in encrypted
            .chunks_exact(self.protected_attributes.len())
            .zip(self.table_entries.iter_mut())
        {
            for (enc, name) in encrypted.iter().zip(self.protected_attributes.iter()) {
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

        let mut output = Vec::with_capacity(self.table_entries.len());

        for (primary_key, table_entry, terms) in self.table_entries.into_iter() {
            let table_entries = terms
                .into_iter()
                .enumerate()
                .map(|(i, (index_name, index_type, term))| {
                    Ok(Sealed(table_entry.clone().set_term(term).set_sk(
                        b64_encode(hmac(
                            &format_term_key(&primary_key.sk, index_name, index_type, i),
                            Some(primary_key.pk.as_str()),
                            self.cipher,
                        )?),
                    )))
                })
                .chain(once(Ok(Sealed(table_entry.clone()))))
                .collect::<Result<_, SealError>>()?;

            output.push((primary_key, table_entries));
        }

        Ok(output)
    }

    pub async fn seal_all<T>(
        records: Vec<T>,
        cipher: &'e Encryption<C>,
    ) -> Result<Vec<(PrimaryKeyParts, Vec<Sealed>)>, SealError>
    where
        T: Searchable + Encryptable,
    {
        let protected_attributes = T::protected_attributes();
        let protected_indexes = T::protected_indexes();

        let mut sealer = Sealer::new(
            cipher,
            T::is_partition_key_encrypted(),
            T::is_sort_key_encrypted(),
            T::index_by_name,
            &protected_attributes,
            &protected_indexes,
            T::type_name(),
        );

        sealer.reserve(records.len());

        let records_meta = records
            .iter()
            .map(|record| {
                (
                    record.all_attributes_for_indexes(),
                    record.partition_key(),
                    record.sort_key(),
                )
            })
            .collect_vec();

        let unsealed_records = records
            .into_iter()
            .map(|record| record.into_unsealed())
            .collect_vec();

        for ((all_attributes_for_indexes, pk, sk), unsealed) in
            records_meta.into_iter().zip(unsealed_records.iter())
        {
            sealer.push(unsealed, pk, sk, all_attributes_for_indexes)?;
        }

        sealer.finalize().await
    }

    pub async fn seal<T>(
        record: T,
        cipher: &'e Encryption<C>,
    ) -> Result<(PrimaryKeyParts, Vec<Sealed>), SealError>
    where
        T: Encryptable + Searchable,
    {
        let mut result = Self::seal_all(vec![record], cipher).await?;

        if result.len() == 1 {
            Ok(result.remove(0))
        } else {
            Err(SealError::AssertionFailed(format!(
                "Expected seal_all to return 1 result but got {}",
                result.len()
            )))
        }
    }
}
