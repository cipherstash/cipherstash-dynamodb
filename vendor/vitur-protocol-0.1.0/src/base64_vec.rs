use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(deserializer)?;
    base64::decode(s).map_err(D::Error::custom)
}

pub(crate) fn serialize<S: Serializer>(v: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&base64::encode(v))
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    #[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
    struct TestStruct {
        #[serde(with = "super")]
        first: Vec<u8>,
    }

    #[test]
    fn test_serialize_struct() {
        assert_eq!(
            serde_json::to_string(&TestStruct { first: vec![1; 16] })
                .expect("Failed to serialize TestStruct"),
            r#"{"first":"AQEBAQEBAQEBAQEBAQEBAQ=="}"#
        );
    }

    #[test]
    fn test_deserialize_struct() {
        let x: TestStruct = serde_json::from_value(json!({
            "first": base64::encode(vec![ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        }))
        .expect("Failed to load TestStruct from json");

        assert_eq!(
            x,
            TestStruct {
                first: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
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
}
