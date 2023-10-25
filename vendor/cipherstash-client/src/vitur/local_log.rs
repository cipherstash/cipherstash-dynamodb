use std::io::Write;
use std::path::Path;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use vitur_client::EncryptedRecord;

#[derive(Debug, Serialize, Deserialize)]
struct JWTSub {
    sub: String,
}

fn get_sub(access_token: &str) -> Option<String> {
    let parts: Vec<&str> = access_token.split('.').collect();
    if let [_header, payload, ..] = parts[..] {
        URL_SAFE_NO_PAD
            .decode(payload)
            .ok()
            .and_then(|j| serde_json::from_slice(&j).ok())
            .map(|jwt: JWTSub| jwt.sub)
    } else {
        None
    }
}

pub fn log_decryptions(
    records: &[EncryptedRecord],
    access_token: &str,
    log_path: &Path,
) -> Result<(), std::io::Error> {
    let mut log_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(log_path)?;

    let utc_now: DateTime<Utc> = Utc::now();
    let sub = get_sub(access_token).unwrap_or("null".to_string());

    for record in records {
        let tag = STANDARD.encode(&record.tag);
        let descriptor = record.descriptor.as_str();

        writeln!(
            log_file,
            "[{utc_now}] - Tag: {tag} - Descriptor: {descriptor} - Sub: {sub}"
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::{
        engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
        Engine,
    };
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn test_sub_from_access_token_standard() {
        let header = STANDARD.encode(
            json!({
                "alg": "RS256",
                "typ": "JWT",
                "kid": "Tp3HULfJmPGv-ZPXpFrcFEUm5TQY3fh7oK4KliypL4Q"
            })
            .to_string(),
        );

        let payload = STANDARD.encode(json!({
            "workspace": "ws:FdYH6JaSeew3",
            "iss": "http://localhost:3000/",
            "sub": "CS|f29ae45d-e0c4-5382-8e4a-b74eb62a4089",
            "aud": "ap-southeast-2.aws.viturhosted.net",
            "iat": 1676343953,
            "exp": 1676344853,
            "azp": "f29ae45d-e0c4-5382-8e4a-b74eb62a4089",
            "scope": "client_key:generate domain_key:generate data_key:generate data_key:retrieve"
        }).to_string());

        let access_token = [&header, &payload, "my-signature"].join(".");

        let sub = get_sub(&access_token);

        assert_eq!(
            sub,
            Some("CS|f29ae45d-e0c4-5382-8e4a-b74eb62a4089".to_string())
        );
    }

    #[tokio::test]
    async fn test_sub_from_access_token_standard_no_pad() {
        let header = STANDARD_NO_PAD.encode(
            json!({
                "alg": "RS256",
                "typ": "JWT",
                "kid": "Tp3HULfJmPGv-ZPXpFrcFEUm5TQY3fh7oK4KliypL4Q"
            })
            .to_string(),
        );

        let payload = STANDARD_NO_PAD.encode(json!({
            "workspace": "ws:FdYH6JaSeew3",
            "iss": "http://localhost:3000/",
            "sub": "CS|f29ae45d-e0c4-5382-8e4a-b74eb62a4089",
            "aud": "ap-southeast-2.aws.viturhosted.net",
            "iat": 1676343953,
            "exp": 1676344853,
            "azp": "f29ae45d-e0c4-5382-8e4a-b74eb62a4089",
            "scope": "client_key:generate domain_key:generate data_key:generate data_key:retrieve"
        }).to_string());

        let access_token = [&header, &payload, "my-signature"].join(".");

        let sub = get_sub(&access_token);

        assert_eq!(
            sub,
            Some("CS|f29ae45d-e0c4-5382-8e4a-b74eb62a4089".to_string())
        );
    }

    #[tokio::test]
    async fn test_sub_from_access_token_url_safe() {
        let header = URL_SAFE.encode(
            json!({
                "alg": "RS256",
                "typ": "JWT",
                "kid": "Tp3HULfJmPGv-ZPXpFrcFEUm5TQY3fh7oK4KliypL4Q"
            })
            .to_string(),
        );

        let payload = URL_SAFE.encode(json!({
            "workspace": "ws:FdYH6JaSeew3",
            "iss": "http://localhost:3000/",
            "sub": "CS|f29ae45d-e0c4-5382-8e4a-b74eb62a4089",
            "aud": "ap-southeast-2.aws.viturhosted.net",
            "iat": 1676343953,
            "exp": 1676344853,
            "azp": "f29ae45d-e0c4-5382-8e4a-b74eb62a4089",
            "scope": "client_key:generate domain_key:generate data_key:generate data_key:retrieve"
        }).to_string());

        let access_token = [&header, &payload, "my-signature"].join(".");

        let sub = get_sub(&access_token);

        assert_eq!(
            sub,
            Some("CS|f29ae45d-e0c4-5382-8e4a-b74eb62a4089".to_string())
        );
    }

    #[tokio::test]
    async fn test_sub_from_access_token_url_safe_no_pad() {
        let header = URL_SAFE_NO_PAD.encode(
            json!({
                "alg": "RS256",
                "typ": "JWT",
                "kid": "Tp3HULfJmPGv-ZPXpFrcFEUm5TQY3fh7oK4KliypL4Q"
            })
            .to_string(),
        );

        let payload = URL_SAFE_NO_PAD.encode(json!({
            "workspace": "ws:FdYH6JaSeew3",
            "iss": "http://localhost:3000/",
            "sub": "CS|f29ae45d-e0c4-5382-8e4a-b74eb62a4089",
            "aud": "ap-southeast-2.aws.viturhosted.net",
            "iat": 1676343953,
            "exp": 1676344853,
            "azp": "f29ae45d-e0c4-5382-8e4a-b74eb62a4089",
            "scope": "client_key:generate domain_key:generate data_key:generate data_key:retrieve"
        }).to_string());

        let access_token = [&header, &payload, "my-signature"].join(".");

        let sub = get_sub(&access_token);

        assert_eq!(
            sub,
            Some("CS|f29ae45d-e0c4-5382-8e4a-b74eb62a4089".to_string())
        );
    }

    #[tokio::test]
    async fn test_sub_from_access_token_with_test_string() {
        let access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlRwM0hVTGZKbVBHdi1aUFhwRnJjRkVVbTVUUVkzZmg3b0s0S2xpeXBMNFEifQ.eyJ3b3Jrc3BhY2UiOiJ3czpGZFlINkphU2VldzMiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvIiwic3ViIjoiQ1N8ZjI5YWU0NWQtZTBjNC01MzgyLThlNGEtYjc0ZWI2MmE0MDg5IiwiYXVkIjoiYXAtc291dGhlYXN0LTIuYXdzLnZpdHVyaG9zdGVkLm5ldCIsImlhdCI6MTY3NjM0Mzk1MywiZXhwIjoxNjc2MzQ0ODUzLCJhenAiOiJmMjlhZTQ1ZC1lMGM0LTUzODItOGU0YS1iNzRlYjYyYTQwODkiLCJzY29wZSI6ImNsaWVudF9rZXk6Z2VuZXJhdGUgZG9tYWluX2tleTpnZW5lcmF0ZSBkYXRhX2tleTpnZW5lcmF0ZSBkYXRhX2tleTpyZXRyaWV2ZSJ9.my-signature";

        let sub = get_sub(access_token);

        assert_eq!(
            sub,
            Some("CS|f29ae45d-e0c4-5382-8e4a-b74eb62a4089".to_string())
        );
    }

    #[tokio::test]
    async fn test_sub_from_access_token_with_another_token() {
        let access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkwzLUkyR0JHV0ZtYWpJUXEtdWlneUlTVzJRcGREWS1TOHM0WkgzQmxlczAifQ.eyJ3b3Jrc3BhY2UiOiJ3czpSN01NU1BOQ0ZSWTdaQk5IIiwiaXNzIjoiaHR0cHM6Ly9jb25zb2xlLmNpcGhlcnN0YXNoLmNvbS8iLCJzdWIiOiJDU3xkYzdkMzE2YS01ZjkwLTVhMWItOWIwNy0xYWNhZGVkYzFhZGUiLCJhdWQiOiJhcC1zb3V0aGVhc3QtMi5hd3Mudml0dXJob3N0ZWQubmV0IiwiaWF0IjoxNjc2MzYwOTY2LCJleHAiOjE2NzYzNjgxNjYsImF6cCI6ImRjN2QzMTZhLTVmOTAtNWExYi05YjA3LTFhY2FkZWRjMWFkZSIsInNjb3BlIjoiY2xpZW50X2tleTpnZW5lcmF0ZSBkb21haW5fa2V5OmdlbmVyYXRlIGRhdGFfa2V5OmdlbmVyYXRlIGRhdGFfa2V5OnJldHJpZXZlIn0.another-signature";

        let sub = get_sub(access_token);

        assert_eq!(
            sub,
            Some("CS|dc7d316a-5f90-5a1b-9b07-1acadedc1ade".to_string())
        );
    }
}
