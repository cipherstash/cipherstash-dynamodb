use static_assertions::assert_impl_all;
use std::error::Error as StdError;
use thiserror::Error;

pub trait RetryableError {
    fn can_retry(&self) -> bool;
}

type ShareableError = Box<dyn StdError + Send + Sync>;

#[derive(Debug)]
pub enum ViturRequestErrorKind {
    PrepareRequest,
    SendRequest,
    NotFound,
    FailureResponse,
    ParseResponse,
    Other,
}

impl std::fmt::Display for ViturRequestErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::PrepareRequest => "PrepareRequest",
                Self::SendRequest => "SendRequest",
                Self::NotFound => "NotFound",
                Self::FailureResponse => "FailureResponse",
                Self::ParseResponse => "ParseResponse",
                Self::Other => "Other",
            }
        )
    }
}

#[derive(Debug, Error)]
#[error("{kind}: {message}: {error}")]
pub struct ViturRequestError {
    pub kind: ViturRequestErrorKind,
    pub message: &'static str,
    pub error: ShareableError,
    can_retry: bool,
}

// ViturRequestError should be able to be sent and shared between threads to be able to support
// async as well as `anyhow!` for async.
assert_impl_all!(ViturRequestError: Send, Sync);

impl ViturRequestError {
    #[inline]
    pub fn prepare(message: &'static str, error: impl StdError + 'static + Send + Sync) -> Self {
        Self {
            kind: ViturRequestErrorKind::PrepareRequest,
            message,
            error: Box::new(error),
            can_retry: false,
        }
    }

    #[inline]
    pub fn parse(message: &'static str, error: impl StdError + 'static + Send + Sync) -> Self {
        Self {
            kind: ViturRequestErrorKind::ParseResponse,
            message,
            error: Box::new(error),
            can_retry: false,
        }
    }

    #[inline]
    pub fn send(message: &'static str, error: impl StdError + 'static + Send + Sync) -> Self {
        Self {
            kind: ViturRequestErrorKind::SendRequest,
            message,
            error: Box::new(error),
            can_retry: false,
        }
    }

    #[inline]
    pub fn not_found(message: &'static str, error: impl StdError + 'static + Send + Sync) -> Self {
        Self {
            kind: ViturRequestErrorKind::NotFound,
            message,
            error: Box::new(error),
            can_retry: false,
        }
    }

    #[inline]
    pub fn response(message: &'static str, error: impl StdError + 'static + Send + Sync) -> Self {
        Self {
            kind: ViturRequestErrorKind::FailureResponse,
            message,
            error: Box::new(error),
            can_retry: false,
        }
    }

    #[inline]
    pub fn other(message: &'static str, error: impl StdError + 'static + Send + Sync) -> Self {
        Self {
            kind: ViturRequestErrorKind::Other,
            message,
            error: Box::new(error),
            can_retry: false,
        }
    }

    pub fn with_retryable(mut self, can_retry: bool) -> Self {
        self.can_retry = can_retry;
        self
    }

    pub fn retryable(self) -> Self {
        self.with_retryable(true)
    }
}

impl RetryableError for ViturRequestError {
    fn can_retry(&self) -> bool {
        self.can_retry
    }
}
