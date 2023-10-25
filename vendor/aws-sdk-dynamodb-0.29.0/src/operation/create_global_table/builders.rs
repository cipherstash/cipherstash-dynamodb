// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::create_global_table::_create_global_table_output::CreateGlobalTableOutputBuilder;

pub use crate::operation::create_global_table::_create_global_table_input::CreateGlobalTableInputBuilder;

impl CreateGlobalTableInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::create_global_table::CreateGlobalTableOutput,
        ::aws_smithy_http::result::SdkError<
            crate::operation::create_global_table::CreateGlobalTableError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.create_global_table();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `CreateGlobalTable`.
///
/// <p>Creates a global table from an existing table. A global table creates a replication relationship between two or more DynamoDB tables with the same table name in the provided Regions. </p> <important>
/// <p>This operation only applies to <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/globaltables.V1.html">Version 2017.11.29 (Legacy)</a> of global tables. We recommend using <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/globaltables.V2.html">Version 2019.11.21 (Current)</a> when creating new global tables, as it provides greater flexibility, higher efficiency and consumes less write capacity than 2017.11.29 (Legacy). To determine which version you are using, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/globaltables.DetermineVersion.html">Determining the version</a>. To update existing global tables from version 2017.11.29 (Legacy) to version 2019.11.21 (Current), see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_upgrade.html"> Updating global tables</a>. </p>
/// </important>
/// <p>If you want to add a new replica table to a global table, each of the following conditions must be true:</p>
/// <ul>
/// <li> <p>The table must have the same primary key as all of the other replicas.</p> </li>
/// <li> <p>The table must have the same name as all of the other replicas.</p> </li>
/// <li> <p>The table must have DynamoDB Streams enabled, with the stream containing both the new and the old images of the item.</p> </li>
/// <li> <p>None of the replica tables in the global table can contain any data.</p> </li>
/// </ul>
/// <p> If global secondary indexes are specified, then the following conditions must also be met: </p>
/// <ul>
/// <li> <p> The global secondary indexes must have the same name. </p> </li>
/// <li> <p> The global secondary indexes must have the same hash key and sort key (if present). </p> </li>
/// </ul>
/// <p> If local secondary indexes are specified, then the following conditions must also be met: </p>
/// <ul>
/// <li> <p> The local secondary indexes must have the same name. </p> </li>
/// <li> <p> The local secondary indexes must have the same hash key and sort key (if present). </p> </li>
/// </ul> <important>
/// <p> Write capacity settings should be set consistently across your replica tables and secondary indexes. DynamoDB strongly recommends enabling auto scaling to manage the write capacity settings for all of your global tables replicas and indexes. </p>
/// <p> If you prefer to manage write capacity settings manually, you should provision equal replicated write capacity units to your replica tables. You should also provision equal replicated write capacity units to matching secondary indexes across your global table. </p>
/// </important>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct CreateGlobalTableFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::create_global_table::builders::CreateGlobalTableInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl CreateGlobalTableFluentBuilder {
    /// Creates a new `CreateGlobalTable`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the CreateGlobalTable as a reference.
    pub fn as_input(&self) -> &crate::operation::create_global_table::builders::CreateGlobalTableInputBuilder {
        &self.inner
    }
    /// Sends the request and returns the response.
    ///
    /// If an error occurs, an `SdkError` will be returned with additional details that
    /// can be matched against.
    ///
    /// By default, any retryable failures will be retried twice. Retry behavior
    /// is configurable with the [RetryConfig](aws_smithy_types::retry::RetryConfig), which can be
    /// set when configuring the client.
    pub async fn send(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_global_table::CreateGlobalTableOutput,
        ::aws_smithy_http::result::SdkError<
            crate::operation::create_global_table::CreateGlobalTableError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self.inner.build().map_err(::aws_smithy_http::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::create_global_table::CreateGlobalTable::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::create_global_table::CreateGlobalTable::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being
    /// sent.
    // TODO(enableNewSmithyRuntimeCleanup): Remove `async` and `Result` once we switch to orchestrator
    pub async fn customize(
        self,
    ) -> ::std::result::Result<
        crate::client::customize::orchestrator::CustomizableOperation<
            crate::operation::create_global_table::CreateGlobalTableOutput,
            crate::operation::create_global_table::CreateGlobalTableError,
        >,
        ::aws_smithy_http::result::SdkError<crate::operation::create_global_table::CreateGlobalTableError>,
    > {
        ::std::result::Result::Ok(crate::client::customize::orchestrator::CustomizableOperation {
            customizable_send: ::std::boxed::Box::new(move |config_override| {
                ::std::boxed::Box::pin(async { self.config_override(config_override).send().await })
            }),
            config_override: None,
            interceptors: vec![],
            runtime_plugins: vec![],
        })
    }
    pub(crate) fn config_override(mut self, config_override: impl Into<crate::config::Builder>) -> Self {
        self.set_config_override(Some(config_override.into()));
        self
    }

    pub(crate) fn set_config_override(&mut self, config_override: Option<crate::config::Builder>) -> &mut Self {
        self.config_override = config_override;
        self
    }
    /// <p>The global table name.</p>
    pub fn global_table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.global_table_name(input.into());
        self
    }
    /// <p>The global table name.</p>
    pub fn set_global_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_global_table_name(input);
        self
    }
    /// <p>The global table name.</p>
    pub fn get_global_table_name(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_global_table_name()
    }
    /// Appends an item to `ReplicationGroup`.
    ///
    /// To override the contents of this collection use [`set_replication_group`](Self::set_replication_group).
    ///
    /// <p>The Regions where the global table needs to be created.</p>
    pub fn replication_group(mut self, input: crate::types::Replica) -> Self {
        self.inner = self.inner.replication_group(input);
        self
    }
    /// <p>The Regions where the global table needs to be created.</p>
    pub fn set_replication_group(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Replica>>) -> Self {
        self.inner = self.inner.set_replication_group(input);
        self
    }
    /// <p>The Regions where the global table needs to be created.</p>
    pub fn get_replication_group(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Replica>> {
        self.inner.get_replication_group()
    }
}
