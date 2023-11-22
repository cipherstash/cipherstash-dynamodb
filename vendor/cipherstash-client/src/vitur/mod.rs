pub mod errors;
mod local_log;

use std::path::{Path, PathBuf};

use crate::credentials::{vitur_credentials::ViturToken, Credentials};
use url::Url;

use self::{
    errors::{
        CreateClientError, CreateDatasetError, DecryptError, DisableDatasetError,
        EnableDatasetError, EncryptError, ListClientError, ListDatasetError, LoadConfigError,
        ModifyDatasetError, RevokeClientError, SaveConfigError,
    },
    local_log::log_decryptions,
};

use log::debug;

pub use schema::{DatasetConfig, DatasetConfigWithIndexRootKey};
pub use vitur_client::{ClientKey, EncryptPayload, EncryptedRecord, Iv};
pub use vitur_protocol::{CreateClientResponse, Dataset, DatasetClient, RevokeClientResponse};

type ViturClient = vitur_client::Client<vitur_client::HttpConnection>;

pub struct Vitur<C: Credentials<Token = ViturToken>, ClientKeyState = ()> {
    client: ViturClient,
    credentials: C,
    decryption_log_path: Option<PathBuf>,
    client_key: ClientKeyState,
}

pub type ViturWithClientKey<C> = Vitur<C, ClientKey>;

impl<C: Credentials<Token = ViturToken>> Vitur<C> {
    pub fn new(base_url: &Url, credentials: C, decryption_log_path: Option<&Path>) -> Self {
        let mut host = base_url.to_string();
        if host.ends_with('/') {
            host.pop();
        }

        let client = ViturClient::init(host);
        Self {
            client,
            credentials,
            decryption_log_path: decryption_log_path.map(|p| p.to_path_buf()),
            client_key: (),
        }
    }

    pub fn new_with_client_key(
        base_url: &Url,
        credentials: C,
        decryption_log_path: Option<&Path>,
        client_key: ClientKey,
    ) -> ViturWithClientKey<C> {
        let mut host = base_url.to_string();
        if host.ends_with('/') {
            host.pop();
        }

        let client = ViturClient::init(host);

        ViturWithClientKey {
            client,
            credentials,
            decryption_log_path: decryption_log_path.map(|p| p.to_path_buf()),
            client_key,
        }
    }
}

impl<C: Credentials<Token = ViturToken>, K> Vitur<C, K> {
    pub fn log_decryptions(&self, records: &[EncryptedRecord], access_token: &str) {
        if let Some(log_path) = &self.decryption_log_path {
            // ignore log errors
            _ = log_decryptions(records, access_token, log_path);
        }
    }

    pub async fn create_dataset(
        &self,
        name: &str,
        description: &str,
    ) -> Result<Dataset, CreateDatasetError> {
        let access_token = self.credentials.get_token().await?.access_token();

        let dataset = self
            .client
            .create_dataset(name, description, &access_token)
            .await?;
        Ok(dataset)
    }

    pub async fn list_datasets(&self) -> Result<Vec<Dataset>, ListDatasetError> {
        let access_token = self.credentials.get_token().await?.access_token();
        let show_disabled = false;
        let datasets = self
            .client
            .list_datasets(&access_token, show_disabled)
            .await?;

        Ok(datasets)
    }

    pub async fn enable_dataset(&self, dataset_id: &str) -> Result<(), EnableDatasetError> {
        let access_token = self.credentials.get_token().await?.access_token();
        self.client
            .enable_dataset(dataset_id, &access_token)
            .await?;
        Ok(())
    }

    pub async fn disable_dataset(&self, dataset_id: &str) -> Result<(), DisableDatasetError> {
        let access_token = self.credentials.get_token().await?.access_token();
        self.client
            .disable_dataset(dataset_id, &access_token)
            .await?;
        Ok(())
    }

    pub async fn modify_dataset(
        &self,
        dataset_id: &str,
        name: Option<&str>,
        description: Option<&str>,
    ) -> Result<(), ModifyDatasetError> {
        let access_token = self.credentials.get_token().await?.access_token();
        self.client
            .modify_dataset(dataset_id, name, description, &access_token)
            .await?;
        Ok(())
    }

    pub async fn create_client(
        &self,
        name: &str,
        description: &str,
        dataset_id: &str,
    ) -> Result<CreateClientResponse, CreateClientError> {
        let access_token = self.credentials.get_token().await?.access_token();

        let created_client = self
            .client
            .create_client(name, description, dataset_id, &access_token)
            .await?;
        Ok(created_client)
    }

    pub async fn list_clients(&self) -> Result<Vec<DatasetClient>, ListClientError> {
        let access_token = self.credentials.get_token().await?.access_token();
        let clients = self.client.list_clients(&access_token).await?;

        Ok(clients)
    }

    pub async fn revoke_client(
        &self,
        client_id: &str,
    ) -> Result<RevokeClientResponse, RevokeClientError> {
        let access_token = self.credentials.get_token().await?.access_token();
        let response = self.client.revoke_client(client_id, &access_token).await?;

        Ok(response)
    }
}

impl<C: Credentials<Token = ViturToken>> ViturWithClientKey<C> {
    pub async fn save_dataset_config(
        &self,
        config: DatasetConfig,
    ) -> Result<DatasetConfigWithIndexRootKey, SaveConfigError> {
        let access_token = self.credentials.get_token().await?.access_token();
        let created_config = self
            .client
            .save_config(config, &self.client_key, &access_token)
            .await?;

        Ok(created_config)
    }

    pub async fn load_dataset_config(
        &self,
    ) -> Result<DatasetConfigWithIndexRootKey, LoadConfigError> {
        let access_token = self.credentials.get_token().await?.access_token();
        let dataset_config = self
            .client
            .load_config(&self.client_key, &access_token)
            .await?;
        Ok(dataset_config)
    }

    pub async fn encrypt(
        &self,
        payloads: impl IntoIterator<Item = EncryptPayload<'_>>,
    ) -> Result<Vec<EncryptedRecord>, EncryptError> {
        debug!(target: "vitur::encrypt", "encrypting records");
        let payloads: Vec<_> = payloads.into_iter().collect();

        if payloads.is_empty() {
            debug!(target: "vitur::encrypt", "no records to encrypt");
            return Ok(vec![]);
        }

        debug!(target: "vitur::encrypt", "waiting for access token");
        let access_token = self.credentials.get_token().await?.access_token();

        debug!(target: "vitur::encrypt", "got token, encrypting");
        let res = self
            .client
            .encrypt(payloads, &self.client_key, &access_token)
            .await?;

        debug!(target: "vitur::encrypt", "success, encrypted {} records", res.len());
        Ok(res)
    }

    pub async fn encrypt_single(
        &self,
        payload: EncryptPayload<'_>,
    ) -> Result<EncryptedRecord, EncryptError> {
        debug!(target: "vitur::encrypt_single", "encrypting record - waiting for access token");
        let access_token = self.credentials.get_token().await?.access_token();

        debug!(target: "vitur::encrypt_single", "got token, encrypting");
        let res = self
            .client
            .encrypt_single(payload, &self.client_key, &access_token)
            .await?;

        debug!(target: "vitur::encrypt_single", "success");
        Ok(res)
    }

    pub async fn decrypt(
        &self,
        payloads: impl IntoIterator<Item = EncryptedRecord>,
    ) -> Result<Vec<Vec<u8>>, DecryptError> {
        debug!(target: "vitur::decrypt", "decrypting records");
        let payloads: Vec<_> = payloads.into_iter().collect();

        if payloads.is_empty() {
            debug!(target: "vitur::decrypt", "no records to decrypt");
            return Ok(vec![]);
        }

        debug!(target: "vitur::decrypt", "waiting for access token");
        let access_token = self.credentials.get_token().await?.access_token();

        self.log_decryptions(&payloads[..], &access_token);

        debug!(target: "vitur::decrypt", "got token, decrypting {} records", payloads.len());
        let res = self
            .client
            .decrypt(payloads, &self.client_key, &access_token)
            .await?;

        debug!(target: "vitur::decrypt", "success, decrypted {} records", res.len());
        Ok(res)
    }

    pub async fn decrypt_single(&self, payload: EncryptedRecord) -> Result<Vec<u8>, DecryptError> {
        debug!(target: "vitur::decrypt_single", "decrypting record - waiting for access token");
        let access_token = self.credentials.get_token().await?.access_token();

        self.log_decryptions(&[payload.clone()], &access_token);

        debug!(target: "vitur::decrypt_single", "got token, decrypting record");
        let res = self
            .client
            .decrypt_single(payload, &self.client_key, &access_token)
            .await?;

        debug!(target: "vitur::decrypt_single", "success");
        Ok(res)
    }
}
