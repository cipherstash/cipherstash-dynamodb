// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`ListExports`](crate::operation::list_exports::builders::ListExportsFluentBuilder) operation.
    /// This operation supports pagination; See [`into_paginator()`](crate::operation::list_exports::builders::ListExportsFluentBuilder::into_paginator).
    ///
    /// - The fluent builder is configurable:
    ///   - [`table_arn(impl ::std::convert::Into<String>)`](crate::operation::list_exports::builders::ListExportsFluentBuilder::table_arn) / [`set_table_arn(Option<String>)`](crate::operation::list_exports::builders::ListExportsFluentBuilder::set_table_arn): <p>The Amazon Resource Name (ARN) associated with the exported table.</p>
    ///   - [`max_results(i32)`](crate::operation::list_exports::builders::ListExportsFluentBuilder::max_results) / [`set_max_results(Option<i32>)`](crate::operation::list_exports::builders::ListExportsFluentBuilder::set_max_results): <p>Maximum number of results to return per page.</p>
    ///   - [`next_token(impl ::std::convert::Into<String>)`](crate::operation::list_exports::builders::ListExportsFluentBuilder::next_token) / [`set_next_token(Option<String>)`](crate::operation::list_exports::builders::ListExportsFluentBuilder::set_next_token): <p>An optional string that, if supplied, must be copied from the output of a previous call to <code>ListExports</code>. When provided in this manner, the API fetches the next page of results.</p>
    /// - On success, responds with [`ListExportsOutput`](crate::operation::list_exports::ListExportsOutput) with field(s):
    ///   - [`export_summaries(Option<Vec<ExportSummary>>)`](crate::operation::list_exports::ListExportsOutput::export_summaries): <p>A list of <code>ExportSummary</code> objects.</p>
    ///   - [`next_token(Option<String>)`](crate::operation::list_exports::ListExportsOutput::next_token): <p>If this value is returned, there are additional results to be displayed. To retrieve them, call <code>ListExports</code> again, with <code>NextToken</code> set to this value.</p>
    /// - On failure, responds with [`SdkError<ListExportsError>`](crate::operation::list_exports::ListExportsError)
    pub fn list_exports(&self) -> crate::operation::list_exports::builders::ListExportsFluentBuilder {
        crate::operation::list_exports::builders::ListExportsFluentBuilder::new(self.handle.clone())
    }
}
