pub mod compound_indexer;
mod errors;
pub mod match_indexer;
mod ore_indexer;
mod plaintext;
mod text;
pub mod unique_indexer;

use std::ops::Not;

use self::{
    compound_indexer::{Accumulator, ComposableIndex, ComposablePlaintext, CompoundIndex},
    ore_indexer::OreIndexer,
    unique_indexer::UniqueIndexer,
};
use crate::{
    credentials::{
        vitur_credentials::{ViturCredentials, ViturToken},
        Credentials,
    },
    vitur::{errors::DecryptError, ViturWithClientKey},
};
use match_indexer::MatchIndexer;
use schema::{column::IndexType, operator::Operator, ColumnType};
use vitur_client::{EncryptPayload, EncryptedRecord};

// Re-exports
pub use self::{
    errors::{EncryptionError, TypeParseError},
    plaintext::{Plaintext, PlaintextNullVariant, TryFromPlaintext},
};

pub struct Encryption<C: Credentials<Token = ViturToken> = ViturCredentials> {
    // This field is public in order for the Driver to be able to cache
    // configuration and avoid a round trip to Vitur for every database
    // connection.
    pub root_key: [u8; 32],
    client: ViturWithClientKey<C>,
}

impl<Creds: Credentials<Token = ViturToken>> Encryption<Creds> {
    pub fn new(root_key: [u8; 32], client: ViturWithClientKey<Creds>) -> Self {
        Self { root_key, client }
    }

    pub async fn encrypt(
        &self,
        items: impl IntoIterator<Item = (&Plaintext, &str)>,
    ) -> Result<Vec<Option<String>>, EncryptionError> {
        let items = items
            .into_iter()
            .map(|(pt, d)| (pt.is_null().not().then(|| pt.to_vec()), d.to_string()))
            .collect::<Vec<_>>();

        let mut output: Vec<Option<String>> = vec![None; items.len()];
        let mut payloads: Vec<EncryptPayload> = Vec::new();
        let mut payloads_index: Vec<usize> = Vec::new();

        for (i, (plaintext, descriptor)) in items.iter().enumerate() {
            if let Some(msg) = plaintext {
                let payload = EncryptPayload { msg, descriptor };
                payloads.push(payload);
                payloads_index.push(i);
            } else {
                output[i] = None;
            }
        }

        let encrypted_records = self.client.encrypt(payloads).await?;
        for (i, encrypted_record) in payloads_index.iter().zip(encrypted_records) {
            let ciphertext = encrypted_record.to_vec().map(hex::encode)?;
            output[*i] = Some(ciphertext);
        }

        Ok(output)
    }

    pub async fn encrypt_single(
        &self,
        plaintext: &Plaintext,
        descriptor: &str,
    ) -> Result<Option<String>, EncryptionError> {
        if plaintext.is_null() {
            Ok(None)
        } else {
            let plaintext = plaintext.to_vec();

            let ciphertext = self
                .client
                .encrypt_single(EncryptPayload {
                    msg: &plaintext,
                    // TODO: This should be a field_id + record_id before launch
                    descriptor,
                })
                .await?;

            Ok(Some(hex::encode(ciphertext.to_vec()?)))
        }
    }

    pub async fn decrypt_single(&self, ciphertext: &str) -> Result<Plaintext, EncryptionError> {
        let record = EncryptedRecord::from_hex(ciphertext)
            // Urf - errors need some work!
            .map_err(|e| EncryptionError::DecryptError(DecryptError::ViturError(e)))?;

        let decrypted = self.client.decrypt_single(record).await?;

        Ok(Plaintext::from_slice(&decrypted)?)
    }

    /// Like `decrypt` but doesn't expect all values to be decryptable.
    /// This only means that a given input is `None` or the slice is not a
    /// serialized [`EncryptedRecord`].
    /// In the future this could also cover cases
    /// where the caller is not _authorized_ to decrypt a given value.
    ///
    /// As it stands, this function will return an Error if any valid ciphertexts
    /// fail to decrypt.
    ///
    /// Items in the returned vec wil be in the same order as the input
    /// but any values that are unable to be decrypted will be returned as `None`.
    ///
    pub async fn maybe_decrypt<I, C>(
        &self,
        ciphertexts: I,
    ) -> Result<Vec<Option<Plaintext>>, EncryptionError>
    where
        I: IntoIterator<Item = Option<C>>,
        C: AsRef<[u8]>,
    {
        let records: (Vec<bool>, Vec<EncryptedRecord>) =
            ciphertexts
                .into_iter()
                .fold(Default::default(), |(mut all, mut target), hex_str| {
                    if let Some(rec) = hex_str
                        .map(hex::decode)
                        .transpose()
                        .unwrap_or(None)
                        .and_then(|bytes| EncryptedRecord::from_slice(&bytes).ok())
                    {
                        target.push(rec);
                        all.push(true);
                    } else {
                        all.push(false);
                    }
                    (all, target)
                });

        let mut results = self
            .client
            .decrypt(records.1)
            .await?
            .into_iter()
            .map(|bytes| Plaintext::from_slice(&bytes));

        Ok(records
            .0
            .iter()
            .map(|valid| {
                if *valid {
                    results.next().transpose()
                } else {
                    Ok(None)
                }
            })
            .collect::<Result<Vec<Option<Plaintext>>, _>>()?)
    }

    pub async fn decrypt<I, C>(&self, ciphertexts: I) -> Result<Vec<Plaintext>, EncryptionError>
    where
        I: IntoIterator<Item = C>,
        C: AsRef<[u8]>,
    {
        let records = ciphertexts
            .into_iter()
            .map(EncryptedRecord::from_hex)
            .collect::<Result<Vec<EncryptedRecord>, _>>()
            .map_err(|e| EncryptionError::DecryptError(DecryptError::ViturError(e)))?;

        Ok(self
            .client
            .decrypt(records)
            .await?
            .iter()
            .map(|bytes| Plaintext::from_slice(bytes))
            .collect::<Result<Vec<Plaintext>, _>>()?)
    }

    pub fn compound_index<I, P, S>(
        &self,
        index: &CompoundIndex<I>,
        input: P,
        salt: Option<S>,
        term_length: usize,
    ) -> Result<IndexTerm, EncryptionError>
    where
        I: ComposableIndex,
        P: Into<ComposablePlaintext>,
        S: AsRef<[u8]>,
    {
        let acc = salt
            .map(|s| Accumulator::from_salt(s.as_ref()))
            .unwrap_or(Accumulator::empty());

        Ok(index
            .compose_index(self.root_key, input.into(), acc)?
            .truncate(term_length)?
            .into())
    }

    pub fn compound_query<I, P, S>(
        &self,
        index: &CompoundIndex<I>,
        input: P,
        salt: Option<S>,
        term_length: usize,
    ) -> Result<IndexTerm, EncryptionError>
    where
        I: ComposableIndex,
        P: Into<ComposablePlaintext>,
        S: AsRef<[u8]>,
    {
        let acc = salt
            .map(|s| Accumulator::from_salt(s.as_ref()))
            .unwrap_or(Accumulator::empty());

        Ok(index
            .compose_query(self.root_key, input.into(), acc)?
            .exactly_one()?
            .truncate(term_length)?
            .try_into()?)
    }

    pub fn index(
        &self,
        value: &Plaintext,
        index_type: &IndexType,
    ) -> Result<IndexTerm, EncryptionError> {
        match index_type {
            IndexType::Ore => OreIndexer::new(self.root_key)?.encrypt(value),
            IndexType::Unique { token_filters } => UniqueIndexer::new(
                self.root_key,
                token_filters.iter().cloned().map(|x| x.into()).collect(),
            )
            .encrypt(value),
            IndexType::Match {
                tokenizer,
                token_filters,
                k,
                m,
                ..
            } => MatchIndexer::new(
                self.root_key,
                tokenizer.clone(),
                token_filters.to_vec(),
                *k,
                *m,
            )
            .encrypt(value),
        }
    }

    pub fn index_for_operator(
        &self,
        value: &Plaintext,
        index_type: &IndexType,
        operator: &Operator,
        cast_type: &ColumnType,
    ) -> Result<IndexTerm, EncryptionError> {
        // Check if index supports op
        if !index_type.supports(operator, cast_type) {
            return Err(EncryptionError::IndexingError(format!(
                "Unsupported operator ({}) for Index {:?}",
                operator.as_str(),
                index_type
            )));
        }
        match index_type {
            IndexType::Ore => OreIndexer::new(self.root_key)?.encrypt_for_query(value),
            // Unique and Match don't work any differently for queries
            IndexType::Unique { .. } => self.index(value, index_type),
            IndexType::Match { .. } => self.index(value, index_type),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum IndexTerm {
    Binary(Vec<u8>),
    BinaryVec(Vec<Vec<u8>>),
    BitMap(Vec<u16>),
    /// Represents a full ORE Ciphertext (both left and right)
    OreFull(Vec<u8>),
    /// Array of FullOre terms
    OreArray(Vec<Vec<u8>>),
    /// Represents a Left ORE Ciphertext
    OreLeft(Vec<u8>),
    /// NULL index field
    Null,
}

impl IndexTerm {
    pub fn as_binary(self) -> Option<Vec<u8>> {
        if let Self::Binary(x) = self {
            Some(x)
        } else {
            None
        }
    }

    /// Get the index term as a vector of binary terms.
    /// If the term is a single binary term, it will be wrapped in a vec.
    pub fn as_binary_vec(self) -> Option<Vec<Vec<u8>>> {
        match self {
            Self::BinaryVec(x) => Some(x),
            Self::Binary(x) => Some(vec![x]),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use crate::{
        config::vitur_config::ViturConfig,
        credentials::{ClearTokenError, GetTokenError},
        vitur::Vitur,
    };

    use super::*;

    struct ViturTestCredentials {
        token: ViturToken,
    }

    #[async_trait]
    impl Credentials for ViturTestCredentials {
        type Token = ViturToken;

        async fn get_token(&self) -> Result<Self::Token, GetTokenError> {
            Ok(self.token.clone())
        }

        async fn clear_token(&self) -> Result<(), ClearTokenError> {
            Ok(())
        }
    }

    fn create_test_encryption() -> Encryption<ViturTestCredentials> {
        let token = ViturToken {
            access_token: "access_token".to_string(),
            expiry: 0,
        };
        let credentials = ViturTestCredentials { token };
        let root_key = [0; 32];

        let config = ViturConfig::builder()
            .with_env()
            .build_with_client_key()
            .expect("Unable to load Vitur config");

        let vitur_client = Vitur::new_with_client_key(
            &config.base_url(),
            credentials,
            config.decryption_log_path().as_deref(),
            config.client_key(),
        );

        Encryption::new(root_key, vitur_client)
    }

    // Ignore for now because these require a real Vitur instance running
    #[ignore]
    #[tokio::test]
    async fn test_round_trip_single() -> Result<(), Box<dyn std::error::Error>> {
        let encryption = create_test_encryption();
        let value = "hello cipher".into();
        let ciphertext = encryption.encrypt_single(&value, "desc").await?;
        assert_eq!(
            value,
            encryption.decrypt_single(&ciphertext.unwrap()).await?
        );

        Ok(())
    }

    // Ignore for now because these require a real Vitur instance running
    #[ignore]
    #[tokio::test]
    async fn test_round_trip_bulk_decrypt() -> Result<(), Box<dyn std::error::Error>> {
        let encryption = create_test_encryption();

        let plaintexts = vec!["a".into(), "b".into(), "c".into()];

        let mut ciphertexts: Vec<String> = Default::default();
        for (i, plaintext) in plaintexts.iter().enumerate() {
            ciphertexts.push(
                encryption
                    .encrypt_single(plaintext, &format!("value-{i}"))
                    .await?
                    .unwrap(),
            );
        }

        assert_eq!(plaintexts, encryption.decrypt(ciphertexts).await?);

        Ok(())
    }

    // Ignore for now because these require a real Vitur instance running
    #[ignore]
    #[tokio::test]
    async fn test_round_trip_bulk_maybe_decrypt() -> Result<(), Box<dyn std::error::Error>> {
        let encryption = create_test_encryption();

        let p1 = "a".into();
        let p2 = "b".into();
        let p3 = "c".into();

        let mut ciphertexts: Vec<Option<String>> = Default::default();
        for (i, plaintext) in vec![&p1, &p2, &p3].into_iter().enumerate() {
            ciphertexts.push(Some(
                encryption
                    .encrypt_single(plaintext, &format!("value-{i}"))
                    .await?
                    .unwrap(),
            ));
            ciphertexts.push(Some(format!("not-encrypted-{i}")));
        }
        ciphertexts.push(None);

        assert_eq!(
            vec![Some(p1), None, Some(p2), None, Some(p3), None, None],
            encryption.maybe_decrypt(ciphertexts).await?
        );

        Ok(())
    }

    // TODO: Test the other functions and indexers
}
