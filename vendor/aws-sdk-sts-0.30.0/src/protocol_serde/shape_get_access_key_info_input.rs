// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_get_access_key_info_input_input(
    input: &crate::operation::get_access_key_info::GetAccessKeyInfoInput,
) -> Result<::aws_smithy_http::body::SdkBody, ::aws_smithy_http::operation::error::SerializationError> {
    let mut out = String::new();
    #[allow(unused_mut)]
    let mut writer = ::aws_smithy_query::QueryWriter::new(&mut out, "GetAccessKeyInfo", "2011-06-15");
    #[allow(unused_mut)]
    let mut scope_1 = writer.prefix("AccessKeyId");
    if let Some(var_2) = &input.access_key_id {
        scope_1.string(var_2);
    }
    writer.finish();
    Ok(::aws_smithy_http::body::SdkBody::from(out))
}
