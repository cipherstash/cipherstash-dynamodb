use std::time::Duration;

use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};

pub fn create_client() -> ClientWithMiddleware {
    // Calculation: unjittered_wait_for = min_retry_interval * backoff_exponent ^ past_retries_count
    // With backoff_exponent = 2, and min_retry 500ms, we get: 500ms, 1s, 2s, 4s, 8s for first 5 tries.
    let retry_policy = ExponentialBackoff::builder()
        .backoff_exponent(2)
        .retry_bounds(Duration::from_millis(500), Duration::from_secs(1800))
        .build_with_max_retries(5);

    ClientBuilder::new(reqwest::Client::new())
        .with(RetryTransientMiddleware::new_with_policy(retry_policy))
        .build()
}
