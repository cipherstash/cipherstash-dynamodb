// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(clippy::unnecessary_wraps)]
pub fn de_disable_kinesis_streaming_destination_http_error(
    _response_status: u16,
    _response_headers: &::http::header::HeaderMap,
    _response_body: &[u8],
) -> std::result::Result<
    crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationOutput,
    crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationError,
> {
    #[allow(unused_mut)]
    let mut generic_builder = crate::protocol_serde::parse_http_error_metadata(_response_status, _response_headers, _response_body)
        .map_err(crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationError::unhandled)?;
    generic_builder = ::aws_http::request_id::apply_request_id(generic_builder, _response_headers);
    let generic = generic_builder.build();
    let error_code = match generic.code() {
        Some(code) => code,
        None => return Err(crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationError::unhandled(generic)),
    };

    let _error_message = generic.message().map(|msg| msg.to_owned());
    Err(match error_code {
        "InternalServerError" => {
            crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationError::InternalServerError({
                #[allow(unused_mut)]
                let mut tmp = {
                    #[allow(unused_mut)]
                    let mut output = crate::types::error::builders::InternalServerErrorBuilder::default();
                    output = crate::protocol_serde::shape_internal_server_error::de_internal_server_error_json_err(_response_body, output)
                        .map_err(crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationError::unhandled)?;
                    let output = output.meta(generic);
                    output.build()
                };
                if tmp.message.is_none() {
                    tmp.message = _error_message;
                }
                tmp
            })
        }
        "InvalidEndpointException" => {
            crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationError::InvalidEndpointException({
                #[allow(unused_mut)]
                let mut tmp = {
                    #[allow(unused_mut)]
                    let mut output = crate::types::error::builders::InvalidEndpointExceptionBuilder::default();
                    output = crate::protocol_serde::shape_invalid_endpoint_exception::de_invalid_endpoint_exception_json_err(_response_body, output)
                        .map_err(crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationError::unhandled)?;
                    let output = output.meta(generic);
                    output.build()
                };
                if tmp.message.is_none() {
                    tmp.message = _error_message;
                }
                tmp
            })
        }
        "LimitExceededException" => {
            crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationError::LimitExceededException({
                #[allow(unused_mut)]
                let mut tmp = {
                    #[allow(unused_mut)]
                    let mut output = crate::types::error::builders::LimitExceededExceptionBuilder::default();
                    output = crate::protocol_serde::shape_limit_exceeded_exception::de_limit_exceeded_exception_json_err(_response_body, output)
                        .map_err(crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationError::unhandled)?;
                    let output = output.meta(generic);
                    output.build()
                };
                if tmp.message.is_none() {
                    tmp.message = _error_message;
                }
                tmp
            })
        }
        "ResourceInUseException" => {
            crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationError::ResourceInUseException({
                #[allow(unused_mut)]
                let mut tmp = {
                    #[allow(unused_mut)]
                    let mut output = crate::types::error::builders::ResourceInUseExceptionBuilder::default();
                    output = crate::protocol_serde::shape_resource_in_use_exception::de_resource_in_use_exception_json_err(_response_body, output)
                        .map_err(crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationError::unhandled)?;
                    let output = output.meta(generic);
                    output.build()
                };
                if tmp.message.is_none() {
                    tmp.message = _error_message;
                }
                tmp
            })
        }
        "ResourceNotFoundException" => {
            crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationError::ResourceNotFoundException({
                #[allow(unused_mut)]
                let mut tmp = {
                    #[allow(unused_mut)]
                    let mut output = crate::types::error::builders::ResourceNotFoundExceptionBuilder::default();
                    output =
                        crate::protocol_serde::shape_resource_not_found_exception::de_resource_not_found_exception_json_err(_response_body, output)
                            .map_err(crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationError::unhandled)?;
                    let output = output.meta(generic);
                    output.build()
                };
                if tmp.message.is_none() {
                    tmp.message = _error_message;
                }
                tmp
            })
        }
        _ => crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationError::generic(generic),
    })
}

#[allow(clippy::unnecessary_wraps)]
pub fn de_disable_kinesis_streaming_destination_http_response(
    _response_status: u16,
    _response_headers: &::http::header::HeaderMap,
    _response_body: &[u8],
) -> std::result::Result<
    crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationOutput,
    crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationError,
> {
    Ok({
        #[allow(unused_mut)]
        let mut output =
            crate::operation::disable_kinesis_streaming_destination::builders::DisableKinesisStreamingDestinationOutputBuilder::default();
        output = crate::protocol_serde::shape_disable_kinesis_streaming_destination::de_disable_kinesis_streaming_destination(_response_body, output)
            .map_err(crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationError::unhandled)?;
        output._set_request_id(::aws_http::request_id::RequestId::request_id(_response_headers).map(str::to_string));
        output.build()
    })
}

pub fn ser_disable_kinesis_streaming_destination_input(
    input: &crate::operation::disable_kinesis_streaming_destination::DisableKinesisStreamingDestinationInput,
) -> Result<::aws_smithy_http::body::SdkBody, ::aws_smithy_http::operation::error::SerializationError> {
    let mut out = String::new();
    let mut object = ::aws_smithy_json::serialize::JsonObjectWriter::new(&mut out);
    crate::protocol_serde::shape_disable_kinesis_streaming_destination_input::ser_disable_kinesis_streaming_destination_input(&mut object, input)?;
    object.finish();
    Ok(::aws_smithy_http::body::SdkBody::from(out))
}

pub(crate) fn de_disable_kinesis_streaming_destination(
    value: &[u8],
    mut builder: crate::operation::disable_kinesis_streaming_destination::builders::DisableKinesisStreamingDestinationOutputBuilder,
) -> Result<
    crate::operation::disable_kinesis_streaming_destination::builders::DisableKinesisStreamingDestinationOutputBuilder,
    ::aws_smithy_json::deserialize::error::DeserializeError,
> {
    let mut tokens_owned = ::aws_smithy_json::deserialize::json_token_iter(crate::protocol_serde::or_empty_doc(value)).peekable();
    let tokens = &mut tokens_owned;
    ::aws_smithy_json::deserialize::token::expect_start_object(tokens.next())?;
    loop {
        match tokens.next().transpose()? {
            Some(::aws_smithy_json::deserialize::Token::EndObject { .. }) => break,
            Some(::aws_smithy_json::deserialize::Token::ObjectKey { key, .. }) => match key.to_unescaped()?.as_ref() {
                "TableName" => {
                    builder = builder.set_table_name(
                        ::aws_smithy_json::deserialize::token::expect_string_or_null(tokens.next())?
                            .map(|s| s.to_unescaped().map(|u| u.into_owned()))
                            .transpose()?,
                    );
                }
                "StreamArn" => {
                    builder = builder.set_stream_arn(
                        ::aws_smithy_json::deserialize::token::expect_string_or_null(tokens.next())?
                            .map(|s| s.to_unescaped().map(|u| u.into_owned()))
                            .transpose()?,
                    );
                }
                "DestinationStatus" => {
                    builder = builder.set_destination_status(
                        ::aws_smithy_json::deserialize::token::expect_string_or_null(tokens.next())?
                            .map(|s| s.to_unescaped().map(|u| crate::types::DestinationStatus::from(u.as_ref())))
                            .transpose()?,
                    );
                }
                _ => ::aws_smithy_json::deserialize::token::skip_value(tokens)?,
            },
            other => {
                return Err(::aws_smithy_json::deserialize::error::DeserializeError::custom(format!(
                    "expected object key or end object, found: {:?}",
                    other
                )))
            }
        }
    }
    if tokens.next().is_some() {
        return Err(::aws_smithy_json::deserialize::error::DeserializeError::custom(
            "found more JSON tokens after completing parsing",
        ));
    }
    Ok(builder)
}
