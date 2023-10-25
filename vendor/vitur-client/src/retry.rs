use std::future::Future;
use std::time::Duration;
use vitur_protocol::RetryableError;

pub struct RetryOpts {
    max_retries: u32,
    max_backoff: Duration,
    retry_strategy: fn(u32, &RetryOpts) -> Duration,
}

pub fn default_exponential_backoff(count: u32, opts: &RetryOpts) -> Duration {
    Duration::from_millis((100 * 2_u64.pow(count)).min(opts.max_backoff.as_millis() as _))
}

impl Default for RetryOpts {
    fn default() -> Self {
        Self {
            max_retries: 5,
            max_backoff: Duration::from_secs(2),
            retry_strategy: default_exponential_backoff,
        }
    }
}

/// Retry an async callback if the error returned can be retried up until the limits specified in
/// the [`RetryOpts`].
pub async fn with_retries<T, E: RetryableError, F: Future<Output = Result<T, E>>>(
    mut callback: impl FnMut() -> F,
    opts: RetryOpts,
) -> Result<T, E> {
    let mut count: u32 = 0;

    loop {
        let result = callback().await;

        match result {
            Err(e) => {
                if e.can_retry() && count < opts.max_retries {
                    tokio::time::sleep((opts.retry_strategy)(count, &opts)).await;
                    count += 1;
                    continue;
                }

                return Err(e);
            }
            Ok(t) => return Ok(t),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use super::*;

    #[derive(Debug)]
    struct TestError {
        can_retry: bool,
    }

    impl RetryableError for TestError {
        fn can_retry(&self) -> bool {
            self.can_retry
        }
    }

    fn linear_retry(count: u32, _opts: &RetryOpts) -> Duration {
        Duration::from_millis(count as _)
    }

    #[tokio::test]
    async fn test_passes_without_retries() {
        let count = Arc::new(AtomicUsize::new(0));

        with_retries(
            {
                let count = count.clone();

                move || {
                    let count = count.clone();

                    async move {
                        count.fetch_add(1, Ordering::Relaxed);

                        Ok::<(), TestError>(())
                    }
                }
            },
            RetryOpts {
                max_backoff: Duration::from_millis(10),
                max_retries: 3,
                retry_strategy: linear_retry,
            },
        )
        .await
        .expect("Expected to pass");

        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_reaches_max_retries() {
        let count = Arc::new(AtomicUsize::new(0));

        let _ = with_retries(
            {
                let count = count.clone();

                move || {
                    let count = count.clone();

                    async move {
                        count.fetch_add(1, Ordering::Relaxed);

                        Err::<(), _>(TestError { can_retry: true })
                    }
                }
            },
            RetryOpts {
                max_backoff: Duration::from_millis(10),
                max_retries: 5,
                retry_strategy: linear_retry,
            },
        )
        .await
        .expect_err("Expected to fail");

        // 1 initial + 5 retries = 6 tries
        assert_eq!(count.load(Ordering::Relaxed), 6);
    }

    #[tokio::test]
    async fn test_doesnt_retry() {
        let count = Arc::new(AtomicUsize::new(0));

        let _ = with_retries(
            {
                let count = count.clone();

                move || {
                    let count = count.clone();

                    async move {
                        count.fetch_add(1, Ordering::Relaxed);

                        Err::<(), _>(TestError { can_retry: false })
                    }
                }
            },
            RetryOpts {
                max_backoff: Duration::from_millis(10),
                max_retries: 5,
                retry_strategy: linear_retry,
            },
        )
        .await
        .expect_err("Expected to fail");

        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_default_exponential_timeout() {
        let opts = RetryOpts {
            max_backoff: Duration::from_millis(1000),
            ..Default::default()
        };

        assert_eq!(
            default_exponential_backoff(0, &opts),
            Duration::from_millis(100)
        );
        assert_eq!(
            default_exponential_backoff(1, &opts),
            Duration::from_millis(200)
        );
        assert_eq!(
            default_exponential_backoff(2, &opts),
            Duration::from_millis(400)
        );
        assert_eq!(
            default_exponential_backoff(3, &opts),
            Duration::from_millis(800)
        );
        assert_eq!(
            default_exponential_backoff(4, &opts),
            Duration::from_millis(1000)
        );
        assert_eq!(
            default_exponential_backoff(5, &opts),
            Duration::from_millis(1000)
        );
        assert_eq!(
            default_exponential_backoff(6, &opts),
            Duration::from_millis(1000)
        );
    }
}
