use aes_gcm_siv::aead::{Aead, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Key as AesKey, KeyInit, Nonce};
use async_mutex::Mutex;
use key::DataKeyWithTag;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use vitur_config::{DatasetConfig, DatasetConfigWithIndexRootKey};
use vitur_protocol::{
    CreateClientRequest, CreateClientResponse, CreateDatasetRequest, Dataset, DatasetClient,
    DisableDatasetRequest, EnableDatasetRequest, GenerateKeyRequest, GenerateKeySpec, GeneratedKey,
    ListClientRequest, ListDatasetRequest, LoadConfigRequest, ModifyDatasetRequest,
    RetrieveKeyRequest, RetrieveKeySpec, RetrievedKey, RevokeClientRequest, RevokeClientResponse,
    SaveConfigRequest, ViturConnection,
};

use log::trace;

pub mod connection;
pub mod errors;
mod futures;
pub mod key;
mod retry;
mod user_agent;

use crate::futures::map_async_chunked;

pub use errors::*;
pub use key::{ClientKey, DataKey};

pub use recipher::{
    key::{GenRandom, Iv, Key},
    keyset::ProxyKeySet as KeySet,
};

pub use connection::HttpConnection;

#[cfg(test)]
pub mod test_connection;

const INDEX_ROOT_KEY_DESCRIPTOR: &str = "dataset-config-index-root-key";

/// Options for configuring certain behaviours of the [`Client`]
pub struct ClientOpts {
    /// The maximum number of key specs that should be in each generate or retrieve request to
    /// Vitur. Having too large a number of specs per request can panic by exceeding reqwest's max
    /// body size.
    pub max_keys_per_req: usize,
    /// The maximum number of requests that will be spun up per call to `generate_data_keys` or
    /// `retrieve_data_keys`. Having too large a number of concurrent requests can result in
    /// dropped connections which will fail the calls.
    pub max_concurrent_reqs: usize,
}

impl Default for ClientOpts {
    fn default() -> Self {
        Self {
            max_keys_per_req: 500,
            max_concurrent_reqs: 5,
        }
    }
}

pub struct Client<C> {
    rand: Mutex<ChaChaRng>,
    connection: C,
    opts: ClientOpts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedRecord {
    pub iv: Iv,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
    pub descriptor: String,
}

impl EncryptedRecord {
    pub fn to_vec(&self) -> Result<Vec<u8>, serde_cbor::Error> {
        serde_cbor::to_vec(&self)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, DecryptError> {
        serde_cbor::from_slice(bytes).map_err(|e| DecryptError::InvalidCiphertext(e.to_string()))
    }

    pub fn from_hex(hexstr: impl AsRef<[u8]>) -> Result<Self, DecryptError> {
        let bytes = hex::decode(hexstr.as_ref())
            .map_err(|e| DecryptError::InvalidCiphertext(e.to_string()))?;

        Self::from_slice(&bytes)
    }
}

#[derive(Debug, Clone)]
pub struct EncryptPayload<'a> {
    pub msg: Cow<'a, [u8]>,
    pub descriptor: Cow<'a, str>,
    pub iv: Option<Iv>,
}

impl<'a> EncryptPayload<'a> {
    pub fn new(msg: &'a [u8], descriptor: &'a str) -> Self {
        Self {
            msg: Cow::Borrowed(msg),
            descriptor: Cow::Borrowed(descriptor),
            iv: None,
        }
    }
}

pub struct DecryptPayload<'a> {
    pub record: &'a EncryptedRecord,
}

/// The requirements for generating a data key from Vitur.
pub struct GenerateKeyPayload<'a> {
    pub descriptor: &'a str,
    pub iv: Option<Iv>,
}

impl<'a> GenerateKeyPayload<'a> {
    pub fn new(descriptor: &'a str) -> Self {
        Self {
            descriptor,
            iv: None,
        }
    }
}

/// The requirements for retrieving a data key from Vitur.
pub struct RetrieveKeyPayload<'a> {
    pub iv: Iv,
    pub descriptor: &'a str,
    pub tag: &'a [u8],
}

impl Client<HttpConnection> {
    pub fn init(host: String) -> Self {
        Self::with_opts(host, Default::default())
    }

    pub fn with_opts(host: String, opts: ClientOpts) -> Self {
        Self::from_connection_with_opts(HttpConnection::init(host), opts)
    }
}

impl<C: ViturConnection> Client<C> {
    pub fn from_connection(connection: C) -> Self {
        Self::from_connection_with_opts(connection, Default::default())
    }

    pub fn from_connection_with_opts(connection: C, opts: ClientOpts) -> Self {
        Self {
            connection,
            rand: Mutex::new(ChaChaRng::from_entropy()),
            opts,
        }
    }

    pub async fn create_dataset(
        &self,
        name: &str,
        description: &str,
        access_token: &str,
    ) -> Result<Dataset, CreateDatasetError> {
        let req = CreateDatasetRequest {
            name: name.into(),
            description: description.into(),
        };

        let response = self.connection.send(req, access_token).await?;

        Ok(response)
    }

    pub async fn list_datasets(
        &self,
        access_token: &str,
        show_disabled: bool,
    ) -> Result<Vec<Dataset>, ListDatasetError> {
        let response = self
            .connection
            .send(ListDatasetRequest { show_disabled }, access_token)
            .await?;
        Ok(response)
    }

    pub async fn enable_dataset(
        &self,
        dataset_id: &str,
        access_token: &str,
    ) -> Result<(), EnableDatasetError> {
        self.connection
            .send(
                EnableDatasetRequest {
                    dataset_id: Cow::Borrowed(dataset_id),
                },
                access_token,
            )
            .await?;

        Ok(())
    }

    pub async fn disable_dataset(
        &self,
        dataset_id: &str,
        access_token: &str,
    ) -> Result<(), DisableDatasetError> {
        self.connection
            .send(
                DisableDatasetRequest {
                    dataset_id: Cow::Borrowed(dataset_id),
                },
                access_token,
            )
            .await?;

        Ok(())
    }

    pub async fn modify_dataset(
        &self,
        dataset_id: &str,
        name: Option<&str>,
        description: Option<&str>,
        access_token: &str,
    ) -> Result<(), ModifyDatasetError> {
        self.connection
            .send(
                ModifyDatasetRequest {
                    dataset_id: Cow::Borrowed(dataset_id),
                    name: name.map(Cow::Borrowed),
                    description: description.map(Cow::Borrowed),
                },
                access_token,
            )
            .await?;

        Ok(())
    }

    pub async fn create_client(
        &self,
        name: &str,
        description: &str,
        dataset_id: &str,
        access_token: &str,
    ) -> Result<CreateClientResponse, CreateClientError> {
        let req = CreateClientRequest {
            name: name.into(),
            description: description.into(),
            dataset_id: dataset_id.into(),
        };

        let response = self.connection.send(req, access_token).await?;

        Ok(response)
    }

    pub async fn list_clients(
        &self,
        access_token: &str,
    ) -> Result<Vec<DatasetClient>, ListClientError> {
        let response = self
            .connection
            .send(ListClientRequest, access_token)
            .await?;
        Ok(response)
    }

    pub async fn revoke_client(
        &self,
        client_id: &str,
        access_token: &str,
    ) -> Result<RevokeClientResponse, RevokeClientError> {
        let req = RevokeClientRequest {
            client_id: client_id.into(),
        };

        let response = self.connection.send(req, access_token).await?;

        Ok(response)
    }

    /// Generate multiple data keys for an iterator of [`RetrieveKeyPayload`]
    pub async fn retrieve_keys(
        &self,
        keys: impl IntoIterator<Item = RetrieveKeyPayload<'_>>,
        key: &ClientKey,
        access_token: &str,
    ) -> Result<Vec<DataKey>, RetrieveKeyError> {
        let ClientOpts {
            max_keys_per_req,
            max_concurrent_reqs: max_parallel_reqs,
        } = self.opts;

        trace!(target: "vitur_client::retrieve_keys", "preparing payloads");

        let keys = keys
            .into_iter()
            .map(
                |RetrieveKeyPayload {
                     iv,
                     descriptor,
                     tag,
                 }| RetrieveKeySpec {
                    iv,
                    descriptor: descriptor.into(),
                    tag: tag.into(),
                    tag_version: 0,
                },
            )
            .collect::<Vec<_>>();

        trace!(target: "vitur_client::retrieve_keys", "sending requests with {max_parallel_reqs} parallel requests and {max_keys_per_req} keys per request");

        // map_async_chunked will split the retrieve key requests up into chunks and send them to
        // Vitur concurrently. The number of concurrent requests and size of the chunks are passed through from
        // ClientOpts.
        let result = map_async_chunked(
            &keys,
            |keys| async {
                let req = RetrieveKeyRequest {
                    keys: keys.into(),
                    client_id: (&key.key_id).into(),
                };

                trace!(target: "vitur_client::retrieve_keys", "sending request with {} keys", keys.len());

                self.connection
                    .send(req, access_token)
                    .await
                    .map_err(RetrieveKeyError::RequestFailed)
                    .and_then(|res| {
                        // This should never happen with Vitur but check just to be sure.
                        if res.keys.len() != keys.len() {
                            return Err(RetrieveKeyError::InvalidNumberOfKeys {
                                expected: keys.len(),
                                received: res.keys.len(),
                            });
                        }

                        trace!(target: "vitur_client::retrieve_keys", "retrieved keys - creating data keys");

                        Ok(keys
                            .iter()
                            .zip(res.keys)
                            .map(
                                |(RetrieveKeySpec { iv, .. }, RetrievedKey { key_material })| {
                                    DataKey::from_key_material(key, *iv, &key_material)
                                },
                            )
                            .collect())
                    })
            },
            max_keys_per_req,
            max_parallel_reqs,
        )
        .await;

        match &result {
            Err(x) => {
                trace!(target: "vitur_client::retrieve_keys", "failed with error: {x}");
            }
            Ok(x) => {
                trace!(target: "vitur_client::retrieve_keys", "successfully generated {} keys", x.len());
            }
        }

        result
    }

    /// Retrieve a single data key based on it's IV, tag and client key
    pub async fn retrieve_key(
        &self,
        iv: Iv,
        descriptor: &str,
        tag: &[u8],
        key: &ClientKey,
        access_token: &str,
    ) -> Result<DataKey, RetrieveKeyError> {
        let mut keys = self
            .retrieve_keys(
                [RetrieveKeyPayload {
                    iv,
                    descriptor,
                    tag,
                }],
                key,
                access_token,
            )
            .await?;
        debug_assert_eq!(keys.len(), 1);
        Ok(keys.remove(0))
    }

    /// Generate multiple data keys for an iterator of [`GenerateKeyPayload`]
    pub async fn generate_keys(
        &self,
        keys: impl IntoIterator<Item = GenerateKeyPayload<'_>>,
        key: &ClientKey,
        access_token: &str,
    ) -> Result<Vec<DataKeyWithTag>, GenerateKeyError> {
        let ClientOpts {
            max_keys_per_req,
            max_concurrent_reqs: max_parallel_reqs,
        } = self.opts;

        // Use a block here so that the mutex is released as soon as the IV is generated.
        // This stops the mutex being held while the requests to Vitur are being made.
        let keys = {
            trace!(target: "vitur_client::generate_keys", "waiting for rand lock");
            let mut guard = self.rand.lock().await;
            trace!(target: "vitur_client::generate_keys", "got rand lock");

            keys.into_iter()
                .map(|GenerateKeyPayload { descriptor, iv }| {
                    iv.map(Ok)
                        .unwrap_or_else(|| GenRandom::gen_random(&mut *guard))
                        .map(|iv: Iv| GenerateKeySpec {
                            iv,
                            descriptor: descriptor.into(),
                        })
                        .map_err(GenerateKeyError::GenerateIv)
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        trace!(target: "vitur_client::generate_keys", "generated {} key payloads", keys.len());
        trace!(target: "vitur_client::generate_keys", "sending requests with {max_parallel_reqs} parallel requests and {max_keys_per_req} keys per request");

        // map_async_chunked will split the generate key requests up into chunks and send them to
        // Vitur concurrently. The number of concurrent requests and size of the chunks are passed through from
        // ClientOpts.
        let result = map_async_chunked(
            &keys,
            |keys| async {
                let req = GenerateKeyRequest {
                    keys: keys.into(),
                    client_id: (&key.key_id).into(),
                };

                trace!(target: "vitur_client::generate_keys", "sending request with {} keys", keys.len());

                self.connection
                    .send(req, access_token)
                    .await
                    .map_err(GenerateKeyError::RequestFailed)
                    .and_then(|res| {
                        // This should never happen with Vitur but check just to be sure.
                        if res.keys.len() != keys.len() {
                            return Err(GenerateKeyError::InvalidNumberOfKeys {
                                expected: keys.len(),
                                received: res.keys.len(),
                            });
                        }

                        trace!(target: "vitur_client::generate_keys", "sending request with {} keys", keys.len());

                        Ok(keys
                            .iter()
                            .zip(res.keys)
                            .map(
                                |(
                                    GenerateKeySpec { iv, .. },
                                    GeneratedKey { key_material, tag },
                                )| {
                                    DataKeyWithTag::from_key_material(key, *iv, &key_material, tag)
                                },
                            )
                            .collect())
                    })
            },
            max_keys_per_req,
            max_parallel_reqs,
        )
        .await;

        match &result {
            Err(x) => {
                trace!(target: "vitur_client::generate_keys", "failed with error: {x}");
            }
            Ok(x) => {
                trace!(target: "vitur_client::generate_keys", "successfully generated {} keys", x.len());
            }
        }

        result
    }

    /// Generate a single data key for a specific client key and descriptor.
    pub async fn generate_key(
        &self,
        descriptor: &str,
        key: &ClientKey,
        access_token: &str,
    ) -> Result<DataKeyWithTag, GenerateKeyError> {
        let mut keys = self
            .generate_keys(
                [GenerateKeyPayload {
                    descriptor,
                    iv: None,
                }],
                key,
                access_token,
            )
            .await?;
        debug_assert_eq!(keys.len(), 1);
        Ok(keys.remove(0))
    }

    /// Encrypt multiple message and descriptor pairs using randomly generated data keys.
    pub async fn encrypt(
        &self,
        payloads: impl IntoIterator<Item = EncryptPayload<'_>>,
        key: &ClientKey,
        access_token: &str,
    ) -> Result<Vec<EncryptedRecord>, EncryptError> {
        let payloads = payloads.into_iter().collect::<Vec<_>>();
        let mut output = Vec::with_capacity(payloads.len());

        trace!(target: "vitur_client::encrypt", "generating {} keys", payloads.len());

        let keys = self
            .generate_keys(
                payloads
                    .iter()
                    .map(|EncryptPayload { descriptor, iv, .. }| GenerateKeyPayload {
                        descriptor,
                        iv: *iv,
                    }),
                key,
                access_token,
            )
            .await?;

        trace!(target: "vitur_client::encrypt", "generated {} keys - encrypting records", keys.len());

        for (
            EncryptPayload {
                msg, descriptor, ..
            },
            DataKeyWithTag { key, tag },
        ) in payloads.into_iter().zip(keys)
        {
            let DataKey { iv, key } = key;
            let key = AesKey::<Aes256GcmSiv>::from_slice(&key);

            // We're using the first 12 bytes of the IV as the nonce for AES-GCM-SIV.
            // This isn't ideal but it's not possible at the moment to use a 16 byte nonce.
            let nonce = Nonce::from_slice(&iv[..12]);

            let cipher = Aes256GcmSiv::new(key);

            let ciphertext = cipher
                .encrypt(
                    nonce,
                    Payload {
                        msg: &msg,
                        aad: descriptor.as_bytes(),
                    },
                )
                .map_err(EncryptError::FailedToEncrypt)?;

            output.push(EncryptedRecord {
                iv,
                ciphertext,
                tag,
                descriptor: descriptor.to_string(),
            })
        }

        trace!(target: "vitur_client::encrypt", "success - encrypted {} records", output.len());

        Ok(output)
    }

    /// Encrypt a single message with a particular descriptor using a randomly generated data key.
    pub async fn encrypt_single(
        &self,
        payload: EncryptPayload<'_>,
        key: &ClientKey,
        access_token: &str,
    ) -> Result<EncryptedRecord, EncryptError> {
        let mut vec = self.encrypt([payload], key, access_token).await?;
        debug_assert_eq!(vec.len(), 1);
        Ok(vec.remove(0))
    }

    /// Decrypt multiple [`EncryptedRecord`]s using their Vitur data keys and descriptors.
    pub async fn decrypt(
        &self,
        payloads: impl IntoIterator<Item = EncryptedRecord>,
        key: &ClientKey,
        access_token: &str,
    ) -> Result<Vec<Vec<u8>>, DecryptError> {
        let payloads = payloads.into_iter().collect::<Vec<_>>();
        let mut output = Vec::with_capacity(payloads.len());

        trace!(target: "vitur_client::decrypt", "retrieving keys");

        let keys = self
            .retrieve_keys(
                payloads.iter().map(|record| RetrieveKeyPayload {
                    descriptor: &record.descriptor,
                    iv: record.iv,
                    tag: &record.tag,
                }),
                key,
                access_token,
            )
            .await
            .map_err(|e| {
                trace!(target: "vitur_client::decrypt", "failed to retrieve keys");
                e
            })?;

        trace!(target: "vitur_client::decrypt", "retrieved keys - decrypting records");

        for (record, DataKey { key, .. }) in payloads.into_iter().zip(keys) {
            let EncryptedRecord { iv, ciphertext, .. } = record;

            let key = AesKey::<Aes256GcmSiv>::from_slice(&key);

            // We're using the first 12 bytes of the IV as the nonce for AES-GCM-SIV.
            // This isn't ideal but it's not possible at the moment to use a 16 byte nonce.
            let nonce = Nonce::from_slice(&iv[..12]);

            let cipher = Aes256GcmSiv::new(key);

            let plaintext = cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &ciphertext,
                        aad: record.descriptor.as_bytes(),
                    },
                )
                .map_err(DecryptError::FailedToDecrypt)?;

            output.push(plaintext)
        }

        trace!(target: "vitur_client::decrypt", "decrypted {} records", output.len());

        Ok(output)
    }

    /// Decrypt a single [`EncryptedRecord`] using its Vitur data key and descriptor.
    pub async fn decrypt_single(
        &self,
        payload: EncryptedRecord,
        key: &ClientKey,
        access_token: &str,
    ) -> Result<Vec<u8>, DecryptError> {
        let mut vec = self.decrypt([payload], key, access_token).await?;
        debug_assert_eq!(vec.len(), 1);
        Ok(vec.remove(0))
    }

    pub async fn save_config(
        &self,
        dataset_config: DatasetConfig,
        key: &ClientKey,
        access_token: &str,
    ) -> Result<DatasetConfigWithIndexRootKey, SaveConfigError> {
        // Look for an existing dataset_config and attempts to reuse the index_root_key
        // This allows uploading the config multiple times while preserving the existing index_root_key
        // If an existing dataset_config is found, grab the encrypted key, and decrypts it
        // Otherwise, generate a new index_root_key and encrypts it
        // TODO: Should distinguish between an api error vs dataset_config not exist
        let (index_root_key, encrypted_index_root_key): ([u8; 32], EncryptedRecord) = {
            let load_config_req = LoadConfigRequest {
                client_id: (&key.key_id).into(),
            };

            match self.connection.send(load_config_req, access_token).await {
                Ok(response) => {
                    let encrypted_index_root_key =
                        EncryptedRecord::from_slice(&response.encrypted_index_root_key)
                            .map_err(SaveConfigError::DeserializeEncryptedRootKey)?;

                    let index_root_key: [u8; 32] = self
                        .decrypt_single(encrypted_index_root_key.clone(), key, access_token)
                        .await
                        .map_err(SaveConfigError::DecryptRootKey)?
                        .try_into()
                        .map_err(|e: Vec<u8>| SaveConfigError::InvalidIndexRootKeySize(e.len()))?;

                    (index_root_key, encrypted_index_root_key)
                }
                Err(_e) => {
                    let index_root_key: [u8; 32] = {
                        trace!(target: "vitur_client::save_config", "waiting for rand lock");
                        let mut guard = self.rand.lock().await;
                        trace!(target: "vitur_client::save_config", "got rand lock");
                        GenRandom::gen_random(&mut *guard)
                            .map_err(SaveConfigError::CreateRootKey)?
                    };

                    let encrypted_index_root_key = self
                        .encrypt_single(
                            EncryptPayload::new(&index_root_key, INDEX_ROOT_KEY_DESCRIPTOR),
                            key,
                            access_token,
                        )
                        .await
                        .map_err(SaveConfigError::EncryptRootKey)?;

                    (index_root_key, encrypted_index_root_key)
                }
            }
        };

        let req = SaveConfigRequest {
            client_id: (&key.key_id).into(),
            encrypted_index_root_key: encrypted_index_root_key
                .to_vec()
                .map_err(SaveConfigError::SerializeEncryptedRootKey)?,
            dataset_config: Cow::Borrowed(&dataset_config),
        };

        self.connection.send(req, access_token).await?;

        Ok(DatasetConfigWithIndexRootKey {
            config: dataset_config,
            index_root_key,
        })
    }

    pub async fn load_config(
        &self,
        key: &ClientKey,
        access_token: &str,
    ) -> Result<DatasetConfigWithIndexRootKey, LoadConfigError> {
        let req = LoadConfigRequest {
            client_id: (&key.key_id).into(),
        };

        let response = self.connection.send(req, access_token).await?;

        let record = EncryptedRecord::from_slice(&response.encrypted_index_root_key)
            .map_err(LoadConfigError::DeserializeEncryptedRootKey)?;

        let index_root_key = self
            .decrypt_single(record, key, access_token)
            .await?
            .try_into()
            .map_err(|e: Vec<u8>| LoadConfigError::InvalidIndexRootKeySize(e.len()))?;

        Ok(DatasetConfigWithIndexRootKey {
            index_root_key,
            config: response.dataset_config,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use test_connection::*;
    use thiserror::Error;
    use vitur_protocol::*;

    fn client_key() -> ClientKey {
        ClientKey::from_bytes(
            "asd",
            &hex::decode("a4627031a16b7065726d75746174696f6e90010b0a00020d090c07080f060503040e6770325f66726f6da16b7065726d75746174696f6e900d03080c040b0f02060e05070100090a6570325f746fa16b7065726d75746174696f6e900b0a09010e0c020003050f0d07060804627033a16b7065726d75746174696f6e98211819130d11100315120c0917080704181c1818181f0e181e1820181a181b060116000f05181d140a0b02").expect("Failed to decode key material")).expect("Failed to create client key")
    }

    fn build_client(
        callback: impl FnOnce(TestConnectionBuilder) -> TestConnectionBuilder,
    ) -> Client<TestConnection> {
        Client::from_connection(callback(TestConnectionBuilder::new()).build())
    }

    #[derive(Error, Debug)]
    #[error("{0}")]
    struct TestConnectionError(String);

    #[tokio::test]
    async fn test_save_config_root_key_random() {
        let encrypted_index_root_key = Arc::new(Mutex::new(Vec::<u8>::new()));

        let client = build_client(|builder| {
            builder
                .add_failed_response::<LoadConfigRequest>(ViturRequestError::response(
                    "Server returned failure response",
                    TestConnectionError("Status: 404, Body: Not Found".into()),
                ))
                .add_success_response::<GenerateKeyRequest>(GenerateKeyResponse {
                    keys: vec![GeneratedKey {
                        key_material: vec![0; 528].into(),
                        tag: vec![],
                    }],
                })
                .add_success_response::<RetrieveKeyRequest>(RetrieveKeyResponse {
                    keys: vec![RetrievedKey {
                        key_material: vec![0; 528].into(),
                    }],
                })
                .add_success_response::<SaveConfigRequest>(SaveConfigResponse {})
                .add_effect({
                    let encrypted_index_root_key = encrypted_index_root_key.clone();
                    move |mut body: SaveConfigRequest| {
                        // Fish out the generated key from the request
                        std::mem::swap(
                            &mut *encrypted_index_root_key.lock().unwrap(),
                            &mut body.encrypted_index_root_key,
                        );
                    }
                })
        });

        let key = client_key();

        client
            .save_config(DatasetConfig::init(), &key, "token")
            .await
            .unwrap();

        let record =
            EncryptedRecord::from_slice(&encrypted_index_root_key.lock().unwrap()).unwrap();

        let decrypted_root_key = client
            .decrypt_single(record, &key, "token")
            .await
            .expect("Failed to decrypt root key");

        assert_eq!(decrypted_root_key.len(), 32);
    }

    #[tokio::test]
    async fn test_save_config_with_existing_key() {
        let key = client_key();
        let existing_index_root_key = [2_u8; 32];

        let key_client = build_client(|builder| {
            builder.add_success_response::<GenerateKeyRequest>(GenerateKeyResponse {
                keys: vec![GeneratedKey {
                    key_material: vec![0; 528].into(),
                    tag: vec![],
                }],
            })
        });

        let encrypted_existing_index_root_key = key_client
            .encrypt_single(
                EncryptPayload::new(&existing_index_root_key, "dataset-config-index-root-key"),
                &key,
                "token",
            )
            .await
            .expect("Failed to encrypt root key")
            .to_vec()
            .unwrap();

        let encrypted_index_root_key = Arc::new(Mutex::new(Vec::<u8>::new()));

        let client = build_client(|builder| {
            builder
                .add_success_response::<LoadConfigRequest>(LoadConfigResponse {
                    encrypted_index_root_key: encrypted_existing_index_root_key.clone(),
                    dataset_config: DatasetConfig::init(),
                })
                .add_success_response::<RetrieveKeyRequest>(RetrieveKeyResponse {
                    keys: vec![RetrievedKey {
                        key_material: vec![0; 528].into(),
                    }],
                })
                .add_success_response::<GenerateKeyRequest>(GenerateKeyResponse {
                    keys: vec![GeneratedKey {
                        key_material: vec![0; 528].into(),
                        tag: vec![],
                    }],
                })
                .add_success_response::<RetrieveKeyRequest>(RetrieveKeyResponse {
                    keys: vec![RetrievedKey {
                        key_material: vec![0; 528].into(),
                    }],
                })
                .add_success_response::<SaveConfigRequest>(SaveConfigResponse {})
                .add_effect({
                    let encrypted_index_root_key = encrypted_index_root_key.clone();
                    move |mut body: SaveConfigRequest| {
                        // Fish out the generated key from the request
                        std::mem::swap(
                            &mut *encrypted_index_root_key.lock().unwrap(),
                            &mut body.encrypted_index_root_key,
                        );
                    }
                })
        });

        let key = client_key();

        client
            .save_config(DatasetConfig::init(), &key, "token")
            .await
            .unwrap();

        let record =
            EncryptedRecord::from_slice(&encrypted_index_root_key.lock().unwrap()).unwrap();

        let decrypted_root_key = client
            .decrypt_single(record, &key, "token")
            .await
            .expect("Failed to decrypt root key");

        // Check the decrypted root key is the same as the provided one
        assert_eq!(decrypted_root_key, vec![2; 32]);

        // Check the encrypted_existing_index_root_key was not changed
        assert_eq!(
            encrypted_index_root_key.lock().unwrap().to_vec(),
            encrypted_existing_index_root_key
        );
    }

    #[tokio::test]
    async fn test_load_config() {
        let key = client_key();

        let key_client = build_client(|builder| {
            builder.add_success_response::<GenerateKeyRequest>(GenerateKeyResponse {
                keys: vec![GeneratedKey {
                    key_material: vec![0; 528].into(),
                    tag: vec![],
                }],
            })
        });

        let encrypted_index_root_key = key_client
            .encrypt_single(
                EncryptPayload::new(&[3; 32], "dataset-config-index-root-key"),
                &key,
                "token",
            )
            .await
            .expect("Failed to encrypt root key")
            .to_vec()
            .unwrap();

        let client = build_client(move |builder| {
            builder
                .add_success_response::<RetrieveKeyRequest>(RetrieveKeyResponse {
                    keys: vec![RetrievedKey {
                        key_material: vec![0; 528].into(),
                    }],
                })
                .add_success_response::<LoadConfigRequest>(LoadConfigResponse {
                    dataset_config: DatasetConfig::init(),
                    encrypted_index_root_key,
                })
        });

        let config = client
            .load_config(&key, "token")
            .await
            .expect("Failed to load config");

        assert_eq!(config.index_root_key, [3; 32]);
    }

    #[tokio::test]
    async fn test_load_config_key_too_small() {
        let key = client_key();

        let key_client = build_client(|builder| {
            builder.add_success_response::<GenerateKeyRequest>(GenerateKeyResponse {
                keys: vec![GeneratedKey {
                    key_material: vec![0; 528].into(),
                    tag: vec![],
                }],
            })
        });

        let encrypted_index_root_key = key_client
            .encrypt_single(
                EncryptPayload::new(&[3; 16], "dataset-config-index-root-key"),
                &key,
                "token",
            )
            .await
            .expect("Failed to encrypt root key")
            .to_vec()
            .unwrap();

        let client = build_client(move |builder| {
            builder
                .add_success_response::<RetrieveKeyRequest>(RetrieveKeyResponse {
                    keys: vec![RetrievedKey {
                        key_material: vec![0; 528].into(),
                    }],
                })
                .add_success_response::<LoadConfigRequest>(LoadConfigResponse {
                    dataset_config: DatasetConfig::init(),
                    encrypted_index_root_key,
                })
        });

        let err = client
            .load_config(&key, "token")
            .await
            .expect_err("Expected loading config to fail");

        assert_eq!(err.to_string(), "Invalid index root key length: 16");
    }
}
