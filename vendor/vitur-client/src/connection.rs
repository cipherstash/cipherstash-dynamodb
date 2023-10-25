use crate::user_agent::get_user_agent;
use async_trait::async_trait;
use reqwest::{header::HeaderMap, StatusCode};
use serde_json::{from_reader, to_vec};
use std::collections::HashMap;
use thiserror::Error;
use vitur_protocol::{ViturConnection, ViturRequest, ViturRequestError};

pub use serde_json::Error as JsonError;

use crate::retry::with_retries;

pub struct HttpConnection {
    host: String,
    client: reqwest::Client,
}

impl HttpConnection {
    pub fn init(host: String) -> Self {
        Self {
            host,
            client: reqwest::ClientBuilder::new()
                .user_agent(get_user_agent())
                .build()
                .expect("Failed to create HttpConnection"),
        }
    }
}

#[derive(Debug, Error)]
#[error("Received '{received:?}', expected '{expected}', Body: {body:?}, Headers: {headers:?}")]
struct UnexpectedError {
    received: Option<String>,
    expected: &'static str,
    body: Option<String>,
    headers: HashMap<String, String>,
}

#[derive(Debug, Error)]
#[error("Status: {status}, Body: {body:?}, Headers: {headers:?}")]
struct FailureResponse {
    status: StatusCode,
    body: Option<String>,
    headers: HashMap<String, String>,
}

fn header_map_to_hash(map: &HeaderMap) -> HashMap<String, String> {
    map.iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .map(|x| x.to_string())
                .ok()
                .map(|v| (k.to_string(), v))
        })
        .collect()
}

const AWS_AUTHENTICATE_HEADER: &str = "www-authenticate";
const AWS_OIDC_ERROR_MESSAGE: &str =
    "error_description=\"OIDC discovery endpoint communication error\"";
const AWS_JWKS_ERROR_MESSAGE: &str = "error_description=\"JWKS communication error\"";

#[async_trait]
impl ViturConnection for HttpConnection {
    async fn send<Request: ViturRequest>(
        &self,
        request: Request,
        access_token: &str,
    ) -> Result<Request::Response, ViturRequestError> {
        let body = to_vec(&request)
            .map_err(|e| ViturRequestError::prepare("Failed to serialize request", e))?;

        with_retries(
            || async {
                let response = self
                    .client
                    .post(format!("{}/{}", self.host, Request::ENDPOINT))
                    .body(body.clone())
                    .header("content-type", "application/json")
                    .bearer_auth(access_token)
                    .send()
                    .await
                    .map_err(|e| {
                        let can_retry = e.is_timeout() || e.is_connect();

                        ViturRequestError::send("Failed to send request", e)
                            .with_retryable(can_retry)
                    })?;

                let status = response.status();

                if status == 404 {
                    return Err(ViturRequestError::not_found(
                        "Server returned a not found response",
                        FailureResponse {
                            status,
                            headers: header_map_to_hash(response.headers()),
                            body: response.text().await.ok(),
                        },
                    ));
                }

                if !status.is_success() {
                    let headers = header_map_to_hash(response.headers());

                    let can_retry = match status {
                        StatusCode::UNAUTHORIZED => headers
                            .get(AWS_AUTHENTICATE_HEADER)
                            .map(|x| {
                                // If the request was unauthorized and includes the "www-authenticate"
                                // header then it's likely a temporary issue with API gateway.
                                //
                                // If the header contains any of these known messages then retry
                                // the request:
                                x.contains(AWS_OIDC_ERROR_MESSAGE)
                                    || x.contains(AWS_JWKS_ERROR_MESSAGE)
                            })
                            .unwrap_or(false),
                        // 4xx errors
                        StatusCode::REQUEST_TIMEOUT
                        | StatusCode::TOO_MANY_REQUESTS
                        // 5xx errors
                        | StatusCode::INTERNAL_SERVER_ERROR
                        | StatusCode::SERVICE_UNAVAILABLE
                        | StatusCode::GATEWAY_TIMEOUT => true,
                        _ => false,
                    };

                    let err = ViturRequestError::response(
                        "Server returned failure response",
                        FailureResponse {
                            status,
                            headers,
                            body: response.text().await.ok(),
                        },
                    )
                    .with_retryable(can_retry);

                    return Err(err);
                }

                let content_type = response
                    .headers()
                    .get("content-type")
                    .and_then(|x| x.to_str().ok());

                let expected = "application/json";

                if content_type != Some(expected) {
                    return Err(ViturRequestError::parse(
                        "Invalid content type header",
                        UnexpectedError {
                            received: content_type.map(|x| x.into()),
                            expected,
                            headers: header_map_to_hash(response.headers()),
                            body: response.text().await.ok(),
                        },
                    ));
                }

                let response_bytes = response.bytes().await.map_err(|e| {
                    ViturRequestError::parse("Failed to read response body as bytes", e)
                })?;

                from_reader(&response_bytes[..])
                    .map_err(|e| ViturRequestError::parse("Failed to deserialize response body", e))
            },
            Default::default(),
        )
        .await
    }
}
