use async_mutex::Mutex;
use async_trait::async_trait;
use vitur_protocol::{ViturConnection, ViturRequest, ViturRequestError};

type EffectHandlers = Vec<(String, Box<dyn FnOnce(&str) + Send>)>;
type RequestHandlers = Vec<(String, Result<String, ViturRequestError>)>;

pub struct TestConnectionBuilder {
    handlers: RequestHandlers,
    effects: EffectHandlers,
}

impl TestConnectionBuilder {
    pub fn new() -> Self {
        Self {
            handlers: vec![],
            effects: vec![],
        }
    }

    /// Add a matcher for a particular request, returning a success message.
    ///
    /// The matcher is only run once.
    pub fn add_success_response<R: ViturRequest>(mut self, response: R::Response) -> Self {
        self.handlers.push((
            R::ENDPOINT.to_string(),
            Ok(serde_json::to_string(&response)
                .expect("Failed to serialise success response. This shouldn't happen.")),
        ));
        self
    }

    /// Add a matcher for a particular request, returning a [`ViturRequestError`].
    ///
    /// The matcher is only run once.
    pub fn add_failed_response<R: ViturRequest>(mut self, error: ViturRequestError) -> Self {
        self.handlers.push((R::ENDPOINT.to_string(), Err(error)));
        self
    }

    /// Add a matcher for a particular request, running an effect on the body of the request.
    ///
    /// This matcher is only run once.
    pub fn add_effect<R: ViturRequest, H: FnOnce(R) + Send + 'static>(
        mut self,
        handler: H,
    ) -> Self {
        let endpoint = R::ENDPOINT;

        self.effects.push((
            endpoint.to_string(),
            Box::new(move |message| {
                handler(serde_json::from_str(message).expect(
                    "Failed to parse request from message in test effect. This shouldn't happen.",
                ))
            }),
        ));

        self
    }

    pub fn build(self) -> TestConnection {
        TestConnection {
            handlers: Mutex::new(self.handlers),
            effects: Mutex::new(self.effects),
        }
    }
}

impl Default for TestConnectionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct TestConnection {
    handlers: Mutex<RequestHandlers>,
    effects: Mutex<EffectHandlers>,
}

impl TestConnection {
    pub fn builder() -> TestConnectionBuilder {
        TestConnectionBuilder::new()
    }

    pub fn empty() -> Self {
        Self::builder().build()
    }
}

#[async_trait]
impl ViturConnection for TestConnection {
    async fn send<Request: ViturRequest>(
        &self,
        request: Request,
        _access_token: &str,
    ) -> Result<Request::Response, ViturRequestError> {
        let endpoint = Request::ENDPOINT;

        let mut effect_guard = self.effects.lock().await;

        let effect_position = effect_guard.iter().position(|(x, _)| x == endpoint);

        let body = serde_json::to_string(&request)
            .expect("Failed to serialise request body in test connection");

        if let Some(index) = effect_position {
            let (_, effect) = effect_guard.remove(index);
            effect(&body);
        }

        let mut handler_guard = self.handlers.lock().await;

        let index = handler_guard
            .iter()
            .position(|(x, _)| x == endpoint)
            .unwrap_or_else(|| panic!("No handler defined for request: {}", endpoint));

        let (_, body) = handler_guard.remove(index);

        body.map(|x| {
            serde_json::from_str(&x)
                .expect("Failed to parse response body from handler in test connection")
        })
    }
}

mod tests {
    use super::*;

    use vitur_protocol::{GenerateKeyRequest, GenerateKeyResponse};

    #[tokio::test]
    async fn test_success_response() {
        let conn = TestConnection::builder()
            .add_success_response::<GenerateKeyRequest>(GenerateKeyResponse { keys: [].into() })
            .build();

        let res = conn
            .send(
                GenerateKeyRequest {
                    keys: vec![].into(),
                    client_id: "yo".into(),
                },
                "access-token",
            )
            .await
            .unwrap();

        assert_eq!(res.keys.len(), 0);
    }

    #[tokio::test]
    async fn test_failure_response() {
        #[derive(Debug, thiserror::Error)]
        #[error("{0}")]
        struct MyError(&'static str);

        let conn = TestConnection::builder()
            .add_failed_response::<GenerateKeyRequest>(ViturRequestError::other(
                "Oh no",
                MyError("Oops"),
            ))
            .build();

        let err = conn
            .send(
                GenerateKeyRequest {
                    keys: vec![].into(),
                    client_id: "yo".into(),
                },
                "access-token",
            )
            .await
            .expect_err("Expected request to fail");

        assert_eq!(err.to_string(), "Other: Oh no: Oops");
    }

    #[tokio::test]
    #[should_panic]
    async fn test_panic_if_no_handler() {
        let conn = TestConnection::empty();

        let _ = conn
            .send(
                GenerateKeyRequest {
                    keys: vec![].into(),
                    client_id: "yo".into(),
                },
                "access-token",
            )
            .await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_assert_in_effect_fails_test() {
        let conn = TestConnection::builder()
            .add_success_response::<GenerateKeyRequest>(GenerateKeyResponse { keys: [].into() })
            .add_effect(|_: GenerateKeyRequest| panic!("Effect should fail!"))
            .build();

        let _ = conn
            .send(
                GenerateKeyRequest {
                    keys: vec![].into(),
                    client_id: "yo".into(),
                },
                "access-token",
            )
            .await;
    }
}
