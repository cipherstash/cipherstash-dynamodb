use std::sync::Arc;

use async_trait::async_trait;
use log::trace;
use tokio::{sync::Mutex, task::JoinHandle};

use super::{AutoRefreshable, ClearTokenError, Credentials, GetTokenError};

pub struct AutoRefresh<C: AutoRefreshable> {
    refreshable: Arc<Mutex<C>>,
    job: JoinHandle<()>,
}

impl<C: AutoRefreshable> AutoRefresh<C> {
    pub fn new(credentials: C) -> Self {
        let refreshable = Arc::new(Mutex::new(credentials));

        // Starts a background thread to poll and update the console_token
        let refreshable_clone = refreshable.clone();
        let job = tokio::spawn(async move {
            loop {
                let refresh_interval = {
                    trace!(target: "auto_refresh::job", "locking the refreshable");
                    let guard = refreshable_clone.lock().await;

                    trace!(target: "auto_refresh::job", "refreshing");
                    guard.refresh().await
                };

                trace!(target: "auto_refresh::job", "success - waiting {:.2?} before refreshing", refresh_interval);

                tokio::time::sleep(refresh_interval).await;
            }
        });

        Self { refreshable, job }
    }
}

#[async_trait]
impl<C: AutoRefreshable> Credentials for AutoRefresh<C> {
    type Token = C::Token;

    async fn get_token(&self) -> Result<Self::Token, GetTokenError> {
        let guard = self.refreshable.lock().await;
        guard.get_token().await
    }

    async fn clear_token(&self) -> Result<(), ClearTokenError> {
        let guard = self.refreshable.lock().await;
        guard.clear_token().await
    }
}

impl<Credentials: AutoRefreshable> Drop for AutoRefresh<Credentials> {
    fn drop(&mut self) {
        trace!(target: "auto_refresh", "aborting job due to drop");
        self.job.abort();
    }
}
