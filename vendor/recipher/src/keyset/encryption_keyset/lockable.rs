use super::EncryptionKeySet;
use async_trait::async_trait;
use lockable::{
    Aes256GcmSiv, EncryptedRecord, EnvelopeCipher, KeyProvider, LockError, Lockable, Locked,
    UnlockError,
};

#[async_trait]
impl Lockable for EncryptionKeySet {
    type Locked = Vec<u8>;

    async fn unlock_from<K: KeyProvider<Cipher = Aes256GcmSiv>>(
        locked: Locked<Self>,
        cipher: &EnvelopeCipher<K>,
        aad: &str,
    ) -> Result<Self, UnlockError> {
        let er: EncryptedRecord = locked.into_inner().try_into()?;
        let decrypted = cipher.decrypt_with(&er).aad(aad).decrypt().await?;
        let value = serde_cbor::from_slice(&decrypted)
            .map_err(|e| UnlockError::Deserialization(e.to_string()))?;

        Ok(value)
    }

    async fn lock<K: KeyProvider<Cipher = Aes256GcmSiv>>(
        self,
        cipher: &EnvelopeCipher<K>,
        aad: &str,
    ) -> Result<Locked<Self>, LockError> {
        let bytes =
            serde_cbor::to_vec(&self).map_err(|e| LockError::Serialization(e.to_string()))?;

        let inner = cipher
            .encrypt_with(&bytes)
            .aad(aad)
            .encrypt()
            .await?
            .try_into()?;
        Ok(Locked::new(inner))
    }
}
