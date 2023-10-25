use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

pub(crate) fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let s = String::deserialize(deserializer)?;
    let bytes = base64::decode(s).map_err(D::Error::custom)?;
    let len = bytes.len();
    let array: [u8; N] = bytes.try_into().map_err(|_| {
        let expected = format!("[u8; {}]", N);
        D::Error::invalid_length(len, &expected.as_str())
    })?;
    Ok(array)
}

pub(crate) fn serialize<S: Serializer, const N: usize>(
    v: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&base64::encode(v))
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    #[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
    struct TestStruct {
        #[serde(with = "super")]
        first: [u8; 16],
        #[serde(with = "super")]
        second: [u8; 1],
    }

    #[test]
    fn test_serialize_struct() {
        assert_eq!(
            serde_json::to_string(&TestStruct {
                first: [1; 16],
                second: [2]
            })
            .expect("Failed to serialize TestStruct"),
            r#"{"first":"AQEBAQEBAQEBAQEBAQEBAQ==","second":"Ag=="}"#
        );
    }

    #[test]
    fn test_deserialize_struct() {
        let x: TestStruct = serde_json::from_value(json!({
            "first": base64::encode(vec![ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            "second": base64::encode([ 10 ])
        }))
        .expect("Failed to load TestStruct from json");

        assert_eq!(
            x,
            TestStruct {
                first: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                second: [10]
            }
        );
    }

    #[test]
    fn test_fail_missing_member() {
        let err =
            serde_json::from_value::<TestStruct>(json!({})).expect_err("Expected parsing to fail");

        assert_eq!(err.to_string(), "missing field `first`");
    }

    #[test]
    fn test_fail_missing_invalid_base64() {
        let err = serde_json::from_value::<TestStruct>(json!({
            "first": "abcde"
        }))
        .expect_err("Expected parsing to fail");

        assert_eq!(
            err.to_string(),
            "Encoded text cannot have a 6-bit remainder."
        );
    }

    #[test]
    fn test_fail_length_too_short() {
        let err = serde_json::from_value::<TestStruct>(json!({
            "first": base64::encode(vec![ 1, 2, 3 ]),
            "second": base64::encode([ 10 ])
        }))
        .expect_err("Expected parsing to fail");

        assert_eq!(err.to_string(), "invalid length 3, expected [u8; 16]");
    }

    #[test]
    fn test_fail_length_too_long() {
        let err = serde_json::from_value::<TestStruct>(json!({
            "first": base64::encode(vec![ 10; 20 ]),
            "second": base64::encode([ 10 ])
        }))
        .expect_err("Expected parsing to fail");

        assert_eq!(err.to_string(), "invalid length 20, expected [u8; 16]");
    }
}
