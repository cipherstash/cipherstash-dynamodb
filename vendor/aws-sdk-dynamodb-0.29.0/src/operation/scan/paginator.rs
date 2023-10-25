// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
/// Paginator for [`Scan`](crate::operation::scan::Scan)
pub struct ScanPaginator {
    handle: std::sync::Arc<crate::client::Handle>,
    builder: crate::operation::scan::builders::ScanInputBuilder,
    stop_on_duplicate_token: bool,
}

impl ScanPaginator {
    /// Create a new paginator-wrapper
    pub(crate) fn new(handle: std::sync::Arc<crate::client::Handle>, builder: crate::operation::scan::builders::ScanInputBuilder) -> Self {
        Self {
            handle,
            builder,
            stop_on_duplicate_token: true,
        }
    }

    /// Set the page size
    ///
    /// _Note: this method will override any previously set value for `limit`_
    pub fn page_size(mut self, limit: i32) -> Self {
        self.builder.limit = ::std::option::Option::Some(limit);
        self
    }

    /// Create a flattened paginator
    ///
    /// This paginator automatically flattens results using `items`. Queries to the underlying service
    /// are dispatched lazily.
    pub fn items(self) -> crate::operation::scan::paginator::ScanPaginatorItems {
        crate::operation::scan::paginator::ScanPaginatorItems(self)
    }

    /// Stop paginating when the service returns the same pagination token twice in a row.
    ///
    /// Defaults to true.
    ///
    /// For certain operations, it may be useful to continue on duplicate token. For example,
    /// if an operation is for tailing a log file in real-time, then continuing may be desired.
    /// This option can be set to `false` to accommodate these use cases.
    pub fn stop_on_duplicate_token(mut self, stop_on_duplicate_token: bool) -> Self {
        self.stop_on_duplicate_token = stop_on_duplicate_token;
        self
    }

    /// Create the pagination stream
    ///
    /// _Note:_ No requests will be dispatched until the stream is used (eg. with [`.next().await`](tokio_stream::StreamExt::next)).
    pub fn send(
        self,
    ) -> impl ::tokio_stream::Stream<
        Item = ::std::result::Result<
            crate::operation::scan::ScanOutput,
            ::aws_smithy_http::result::SdkError<crate::operation::scan::ScanError, ::aws_smithy_runtime_api::client::orchestrator::HttpResponse>,
        >,
    > + ::std::marker::Unpin {
        // Move individual fields out of self for the borrow checker
        let builder = self.builder;
        let handle = self.handle;
        let runtime_plugins =
            crate::operation::scan::Scan::operation_runtime_plugins(handle.runtime_plugins.clone(), &handle.conf, ::std::option::Option::None);
        ::aws_smithy_async::future::fn_stream::FnStream::new(move |tx| {
            ::std::boxed::Box::pin(async move {
                // Build the input for the first time. If required fields are missing, this is where we'll produce an early error.
                let mut input = match builder.build().map_err(::aws_smithy_http::result::SdkError::construction_failure) {
                    ::std::result::Result::Ok(input) => input,
                    ::std::result::Result::Err(e) => {
                        let _ = tx.send(::std::result::Result::Err(e)).await;
                        return;
                    }
                };
                loop {
                    let resp = crate::operation::scan::Scan::orchestrate(&runtime_plugins, input.clone()).await;
                    // If the input member is None or it was an error
                    let done = match resp {
                        ::std::result::Result::Ok(ref resp) => {
                            let new_token = crate::lens::reflens_scan_output_last_evaluated_key(resp);
                            let is_empty = new_token.map(|token| token.is_empty()).unwrap_or(true);
                            if !is_empty && new_token == input.exclusive_start_key.as_ref() && self.stop_on_duplicate_token {
                                true
                            } else {
                                input.exclusive_start_key = new_token.cloned();
                                is_empty
                            }
                        }
                        ::std::result::Result::Err(_) => true,
                    };
                    if tx.send(resp).await.is_err() {
                        // receiving end was dropped
                        return;
                    }
                    if done {
                        return;
                    }
                }
            })
        })
    }
}

/// Flattened paginator for `ScanPaginator`
///
/// This is created with [`.items()`](ScanPaginator::items)
pub struct ScanPaginatorItems(ScanPaginator);

impl ScanPaginatorItems {
    /// Create the pagination stream
    ///
    /// _Note: No requests will be dispatched until the stream is used (eg. with [`.next().await`](tokio_stream::StreamExt::next))._
    ///
    /// To read the entirety of the paginator, use [`.collect::<Result<Vec<_>, _>()`](tokio_stream::StreamExt::collect).
    pub fn send(
        self,
    ) -> impl ::tokio_stream::Stream<
        Item = ::std::result::Result<
            ::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>,
            ::aws_smithy_http::result::SdkError<crate::operation::scan::ScanError, ::aws_smithy_runtime_api::client::orchestrator::HttpResponse>,
        >,
    > + ::std::marker::Unpin {
        ::aws_smithy_async::future::fn_stream::TryFlatMap::new(self.0.send())
            .flat_map(|page| crate::lens::lens_scan_output_items(page).unwrap_or_default().into_iter())
    }
}
