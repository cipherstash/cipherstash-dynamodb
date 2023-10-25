use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, ops::Deref};
use vitur_config::DatasetConfig;

mod base64_array;
mod base64_vec;
mod error;

pub use error::*;

#[async_trait]
pub trait ViturConnection {
    async fn send<Request: ViturRequest>(
        &self,
        request: Request,
        access_token: &str,
    ) -> Result<Request::Response, ViturRequestError>;
}

pub trait ViturResponse: Serialize + for<'de> Deserialize<'de> + Send {}

#[async_trait]
pub trait ViturRequest: Serialize + for<'de> Deserialize<'de> + Sized + Send {
    type Response: ViturResponse;

    const SCOPE: &'static str;
    const ENDPOINT: &'static str;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDatasetRequest<'a> {
    pub name: Cow<'a, str>,
    pub description: Cow<'a, str>,
}

impl ViturRequest for CreateDatasetRequest<'_> {
    type Response = Dataset;

    const ENDPOINT: &'static str = "create-dataset";
    const SCOPE: &'static str = "dataset:create";
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ListDatasetRequest {
    #[serde(default)]
    pub show_disabled: bool,
}

impl ViturRequest for ListDatasetRequest {
    type Response = Vec<Dataset>;

    const ENDPOINT: &'static str = "list-datasets";
    const SCOPE: &'static str = "dataset:list";
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Dataset {
    pub id: String,
    pub name: String,
    pub description: String,
}

impl ViturResponse for Dataset {}

impl ViturResponse for Vec<Dataset> {}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct EmptyResponse {}

impl ViturResponse for EmptyResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateClientRequest<'a> {
    pub dataset_id: Cow<'a, str>,
    pub name: Cow<'a, str>,
    pub description: Cow<'a, str>,
}

impl<'a> ViturRequest for CreateClientRequest<'a> {
    type Response = CreateClientResponse;

    const ENDPOINT: &'static str = "create-client";
    const SCOPE: &'static str = "client:create";
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateClientResponse {
    pub id: String,
    pub dataset_id: String,
    pub name: String,
    pub description: String,

    #[serde(with = "base64_vec")]
    pub client_key: Vec<u8>,
}

impl ViturResponse for CreateClientResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListClientRequest;

impl ViturRequest for ListClientRequest {
    type Response = Vec<DatasetClient>;

    const ENDPOINT: &'static str = "list-clients";
    const SCOPE: &'static str = "client:list";
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DatasetClient {
    pub id: String,
    pub dataset_id: String,
    pub name: String,
    pub description: String,
}

impl ViturResponse for Vec<DatasetClient> {}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeClientRequest<'a> {
    pub client_id: Cow<'a, str>,
}

impl ViturRequest for RevokeClientRequest<'_> {
    type Response = RevokeClientResponse;

    const ENDPOINT: &'static str = "revoke-client";
    const SCOPE: &'static str = "client:revoke";
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeClientResponse {}

impl ViturResponse for RevokeClientResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ViturKeyMaterial(#[serde(with = "base64_vec")] Vec<u8>);

impl From<Vec<u8>> for ViturKeyMaterial {
    fn from(inner: Vec<u8>) -> Self {
        Self(inner)
    }
}

impl Deref for ViturKeyMaterial {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GeneratedKey {
    pub key_material: ViturKeyMaterial,
    #[serde(with = "base64_vec")]
    pub tag: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateKeyResponse {
    pub keys: Vec<GeneratedKey>,
}

impl ViturResponse for GenerateKeyResponse {}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GenerateKeySpec<'a> {
    #[serde(with = "base64_array")]
    pub iv: [u8; 16],
    pub descriptor: Cow<'a, str>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateKeyRequest<'a> {
    pub client_id: Cow<'a, str>,
    pub keys: Cow<'a, [GenerateKeySpec<'a>]>,
}

impl ViturRequest for GenerateKeyRequest<'_> {
    type Response = GenerateKeyResponse;

    const ENDPOINT: &'static str = "generate-data-key";
    const SCOPE: &'static str = "data_key:generate";
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RetrievedKey {
    pub key_material: ViturKeyMaterial,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RetrieveKeyResponse {
    pub keys: Vec<RetrievedKey>,
}

impl ViturResponse for RetrieveKeyResponse {}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RetrieveKeySpec<'a> {
    #[serde(with = "base64_array")]
    pub iv: [u8; 16],
    pub descriptor: Cow<'a, str>,
    pub tag: Cow<'a, [u8]>,
    pub tag_version: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RetrieveKeyRequest<'a> {
    pub client_id: Cow<'a, str>,
    pub keys: Cow<'a, [RetrieveKeySpec<'a>]>,
}

impl ViturRequest for RetrieveKeyRequest<'_> {
    type Response = RetrieveKeyResponse;

    const ENDPOINT: &'static str = "retrieve-data-key";
    const SCOPE: &'static str = "data_key:retrieve";
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaveConfigRequest<'a> {
    pub client_id: Cow<'a, str>,
    #[serde(with = "base64_vec")]
    pub encrypted_index_root_key: Vec<u8>,
    pub dataset_config: Cow<'a, DatasetConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaveConfigResponse {}

impl ViturResponse for SaveConfigResponse {}

impl ViturRequest for SaveConfigRequest<'_> {
    type Response = SaveConfigResponse;

    const ENDPOINT: &'static str = "save-config";
    const SCOPE: &'static str = "config:write";
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoadConfigRequest<'a> {
    pub client_id: Cow<'a, str>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoadConfigResponse {
    #[serde(with = "base64_vec")]
    pub encrypted_index_root_key: Vec<u8>,
    pub dataset_config: DatasetConfig,
}

impl ViturResponse for LoadConfigResponse {}

impl ViturRequest for LoadConfigRequest<'_> {
    type Response = LoadConfigResponse;

    const ENDPOINT: &'static str = "load-config";
    const SCOPE: &'static str = "config:read";
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DisableDatasetRequest<'a> {
    pub dataset_id: Cow<'a, str>,
}

impl ViturRequest for DisableDatasetRequest<'_> {
    type Response = EmptyResponse;

    const ENDPOINT: &'static str = "disable-dataset";
    const SCOPE: &'static str = "dataset:disable";
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnableDatasetRequest<'a> {
    pub dataset_id: Cow<'a, str>,
}

impl ViturRequest for EnableDatasetRequest<'_> {
    type Response = EmptyResponse;

    const ENDPOINT: &'static str = "enable-dataset";
    const SCOPE: &'static str = "dataset:enable";
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModifyDatasetRequest<'a> {
    pub dataset_id: Cow<'a, str>,

    pub name: Option<Cow<'a, str>>,
    pub description: Option<Cow<'a, str>>,
}

impl ViturRequest for ModifyDatasetRequest<'_> {
    type Response = EmptyResponse;

    const ENDPOINT: &'static str = "modify-dataset";
    const SCOPE: &'static str = "dataset:modify";
}
