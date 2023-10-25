// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_attribute_value_update(
    object: &mut ::aws_smithy_json::serialize::JsonObjectWriter,
    input: &crate::types::AttributeValueUpdate,
) -> Result<(), ::aws_smithy_http::operation::error::SerializationError> {
    if let Some(var_1) = &input.value {
        #[allow(unused_mut)]
        let mut object_2 = object.key("Value").start_object();
        crate::protocol_serde::shape_attribute_value::ser_attribute_value(&mut object_2, var_1)?;
        object_2.finish();
    }
    if let Some(var_3) = &input.action {
        object.key("Action").string(var_3.as_str());
    }
    Ok(())
}
