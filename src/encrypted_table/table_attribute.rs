use super::{ReadConversionError, SealError};
use aws_sdk_dynamodb::{primitives::Blob, types::AttributeValue};
use cipherstash_client::zerokms::EncryptedRecord;
use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

/// Trait for converting `TableAttribute` to `Self`
pub trait TryFromTableAttr: Sized {
    /// Try to convert `value` to `Self`
    fn try_from_table_attr(value: TableAttribute) -> Result<Self, ReadConversionError>;
}

#[derive(Clone, PartialEq, Debug)]
pub enum TableAttribute {
    String(String),
    Number(String),
    Bool(bool),
    Bytes(Vec<u8>),

    StringVec(Vec<String>),
    ByteVec(Vec<Vec<u8>>),
    NumberVec(Vec<String>),
    Map(HashMap<String, TableAttribute>),
    List(Vec<TableAttribute>),

    Null,
}

impl TableAttribute {
    // TODO: Unit test this
    /// Try to convert the `TableAttribute` to an `EncryptedRecord` if it is a `Bytes` variant.
    /// The descriptor of the record is checked against the `descriptor` argument
    /// (which will be verified to be the correct descriptor for the record via AAD).
    ///
    /// If the descriptor does not match, an error is returned and this may indicate that the record
    /// has been tampered with (e.g. via a confused deputy attack).
    pub(crate) fn as_encrypted_record(
        &self,
        descriptor: &str,
    ) -> Result<EncryptedRecord, SealError> {
        if let TableAttribute::Bytes(s) = self {
            EncryptedRecord::from_slice(&s[..])
                .map_err(|_| SealError::AssertionFailed("Could not parse EncryptedRecord".to_string()))
                .and_then(|record| {
                    if record.descriptor == descriptor {
                        Ok(record)
                    } else {
                        Err(SealError::AssertionFailed(format!(
                            "Expected descriptor {}, got {} - WARNING: record may have been tampered with",
                            descriptor,
                            record.descriptor
                        )))
                    }
                })
        } else {
            Err(SealError::AssertionFailed(format!(
                "Expected TableAttribute::Bytes, got {}",
                descriptor
            )))
        }
    }

    pub(crate) fn new_map() -> Self {
        TableAttribute::Map(HashMap::new())
    }

    /// Try to insert a new key-value pair if this is a map.
    /// Returns `Ok(())` if the key-value pair was inserted, otherwise [SealError::AssertionFailed].
    pub(crate) fn try_insert_map(
        &mut self,
        key: impl Into<String>,
        value: impl Into<TableAttribute>,
    ) -> Result<(), SealError> {
        if let Self::Map(map) = self {
            map.insert(key.into(), value.into());
            Ok(())
        } else {
            Err(SealError::AssertionFailed(
                "Expected TableAttribute::Map".to_string(),
            ))
        }
    }
}

macro_rules! impl_try_from_table_attr_helper {
    (number_parse, $ty:ty, $value:ident) => {
        $value
            .parse()
            .map_err(|_| ReadConversionError::ConversionFailed(stringify!($ty).to_string()))
    };
    (simple_parse, $_:ty, $value:ident) => {
        Ok::<_, ReadConversionError>($value)
    };
    (number_from, $_:ident, $value:ident) => {
        TableAttribute::Number($value.to_string())
    };
    (simple_from, $variant:ident, $value:ident) => {
        TableAttribute::$variant($value)
    };
    (
        body,
        $ty:ty,
        $variant:ident,
        $from_impl:ident!($from_args:tt),
        $try_from_impl:ident!($try_from_args:tt)
    ) => {
        impl From<$ty> for TableAttribute {
            fn from(value: $ty) -> Self {
                $from_impl!($from_args, $variant, value)
            }
        }

        impl TryFromTableAttr for $ty {
            fn try_from_table_attr(value: TableAttribute) -> Result<Self, ReadConversionError> {
                let TableAttribute::$variant(value) = value else {
                    return Err(ReadConversionError::ConversionFailed(
                        stringify!($ty).to_string(),
                    ));
                };

                $try_from_impl!($try_from_args, $ty, value)
            }
        }
    };
}

macro_rules! impl_try_from_table_attr {
    () => {};
    (, $($tail:tt)*) => {
        impl_try_from_table_attr!($($tail)*);
    };
    ($ty:ty => Number $($tail:tt)*) => {
        impl_try_from_table_attr_helper!(
            body,
            $ty,
            Number,
            impl_try_from_table_attr_helper!(
                number_from
            ),
            impl_try_from_table_attr_helper!(
                number_parse
            )
        );

        impl_try_from_table_attr!($($tail)*);
    };
    ($ty:ty => $variant:ident $($tail:tt)*) => {
        impl_try_from_table_attr_helper!(
            body,
            $ty,
            $variant,
            impl_try_from_table_attr_helper!(
                simple_from
            ),
            impl_try_from_table_attr_helper!(
                simple_parse
            )
        );

        impl_try_from_table_attr!($($tail)*);
    };
}

// The following implementations are covered by the blanket implementation on Vec<T>
// Vec<String> => StringVec,
// Vec<some number type> => NumberVec,
// Vec<Vec<u8>> => ByteVec,
impl_try_from_table_attr!(
    i16 => Number,
    i32 => Number,
    i64 => Number,
    u16 => Number,
    u32 => Number,
    u64 => Number,
    usize => Number,
    f32 => Number,
    f64  => Number,
    String => String,
    Vec<u8> => Bytes,
    bool => Bool
);

impl From<&str> for TableAttribute {
    fn from(value: &str) -> Self {
        TableAttribute::String(value.to_string())
    }
}

impl<T> TryFromTableAttr for Option<T>
where
    T: TryFromTableAttr,
{
    fn try_from_table_attr(value: TableAttribute) -> Result<Self, ReadConversionError> {
        if matches!(value, TableAttribute::Null) {
            Ok(None)
        } else {
            Ok(Some(T::try_from_table_attr(value)?))
        }
    }
}

impl<T> TryFromTableAttr for Vec<T>
where
    T: TryFromTableAttr,
{
    fn try_from_table_attr(value: TableAttribute) -> Result<Self, ReadConversionError> {
        match value {
            TableAttribute::StringVec(v) => v
                .into_iter()
                .map(TableAttribute::String)
                .map(T::try_from_table_attr)
                .collect(),
            TableAttribute::ByteVec(v) => v
                .into_iter()
                .map(TableAttribute::Bytes)
                .map(T::try_from_table_attr)
                .collect(),
            TableAttribute::NumberVec(v) => v
                .into_iter()
                .map(TableAttribute::Number)
                .map(T::try_from_table_attr)
                .collect(),
            TableAttribute::List(v) => v.into_iter().map(T::try_from_table_attr).collect(),
            _ => Err(ReadConversionError::ConversionFailed(
                std::any::type_name::<Vec<T>>().to_string(),
            )),
        }
    }
}

impl<T> From<Option<T>> for TableAttribute
where
    T: Into<TableAttribute>,
{
    fn from(value: Option<T>) -> Self {
        match value {
            Some(value) => value.into(),
            None => TableAttribute::Null,
        }
    }
}

impl<T> From<Vec<T>> for TableAttribute
where
    T: Into<TableAttribute>,
{
    fn from(value: Vec<T>) -> Self {
        // To determin whether we should produce a
        // Ss, Ns, Bs or a regular list, we will iterate
        // through the list and check if the all are the same
        // variant.
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum IsVariant {
            // base case, we haven't looked at any elements yet.
            Empty,
            // Is String list
            IsSs,
            // Is Number list
            IsNs,
            // Is byte list
            IsBs,
            // Is mixed list
            IsList,
        }

        let len = value.len();
        let (table_attributes, is_variant) = value.into_iter().fold(
            (Vec::with_capacity(len), IsVariant::Empty),
            |(mut acc, mut is_variant), item| {
                let table_attr = item.into();

                // Don't check the variant if we already know it is a mixed list
                if is_variant != IsVariant::IsList {
                    match (&table_attr, is_variant) {
                        (TableAttribute::Bytes(_), IsVariant::Empty)
                        | (TableAttribute::Bytes(_), IsVariant::IsBs) => {
                            is_variant = IsVariant::IsBs
                        }
                        (TableAttribute::Number(_), IsVariant::Empty)
                        | (TableAttribute::Number(_), IsVariant::IsNs) => {
                            is_variant = IsVariant::IsNs
                        }
                        (TableAttribute::String(_), IsVariant::Empty)
                        | (TableAttribute::String(_), IsVariant::IsSs) => {
                            is_variant = IsVariant::IsSs
                        }
                        _ => is_variant = IsVariant::IsList,
                    }
                }

                acc.push(table_attr);
                (acc, is_variant)
            },
        );

        match is_variant {
            IsVariant::IsList | IsVariant::Empty => TableAttribute::List(table_attributes),
            IsVariant::IsSs => {
                let strings = table_attributes
                    .into_iter()
                    .map(|string| {
                        let TableAttribute::String(string) = string else {
                            // We already checked that all the items are strings
                            unreachable!()
                        };

                        string
                    })
                    .collect();

                TableAttribute::StringVec(strings)
            }
            IsVariant::IsNs => {
                let numbers = table_attributes
                    .into_iter()
                    .map(|number| {
                        let TableAttribute::Number(number) = number else {
                            // We already checked that all the items are numbers
                            unreachable!()
                        };

                        number
                    })
                    .collect();

                TableAttribute::NumberVec(numbers)
            }
            IsVariant::IsBs => {
                let bytes = table_attributes
                    .into_iter()
                    .map(|bytes| {
                        let TableAttribute::Bytes(bytes) = bytes else {
                            // We already checked that all the items are bytes
                            unreachable!()
                        };

                        bytes
                    })
                    .collect();

                TableAttribute::ByteVec(bytes)
            }
        }
    }
}

impl From<TableAttribute> for AttributeValue {
    fn from(attribute: TableAttribute) -> Self {
        match attribute {
            TableAttribute::String(s) => AttributeValue::S(s),
            TableAttribute::StringVec(s) => AttributeValue::Ss(s),

            TableAttribute::Number(i) => AttributeValue::N(i),
            TableAttribute::NumberVec(x) => AttributeValue::Ns(x),

            TableAttribute::Bytes(x) => AttributeValue::B(Blob::new(x)),
            TableAttribute::ByteVec(x) => {
                AttributeValue::Bs(x.into_iter().map(Blob::new).collect())
            }

            TableAttribute::Bool(x) => AttributeValue::Bool(x),
            TableAttribute::List(x) => AttributeValue::L(x.into_iter().map(|x| x.into()).collect()),
            TableAttribute::Map(x) => {
                AttributeValue::M(x.into_iter().map(|(k, v)| (k, v.into())).collect())
            }
            TableAttribute::Null => AttributeValue::Null(true),
        }
    }
}

impl From<AttributeValue> for TableAttribute {
    fn from(attribute: AttributeValue) -> Self {
        match attribute {
            AttributeValue::S(s) => TableAttribute::String(s),
            AttributeValue::N(n) => TableAttribute::Number(n),
            AttributeValue::Bool(n) => TableAttribute::Bool(n),
            AttributeValue::B(n) => TableAttribute::Bytes(n.into_inner()),
            AttributeValue::L(l) => {
                TableAttribute::List(l.into_iter().map(TableAttribute::from).collect())
            }
            AttributeValue::M(l) => TableAttribute::Map(
                l.into_iter()
                    .map(|(k, v)| (k, TableAttribute::from(v)))
                    .collect(),
            ),
            AttributeValue::Bs(x) => {
                TableAttribute::ByteVec(x.into_iter().map(|x| x.into_inner()).collect())
            }
            AttributeValue::Ss(x) => TableAttribute::StringVec(x),
            AttributeValue::Ns(x) => TableAttribute::NumberVec(x),
            AttributeValue::Null(_) => TableAttribute::Null,

            x => panic!("Unsupported Dynamo attribute value: {x:?}"),
        }
    }
}

impl<K, V> From<HashMap<K, V>> for TableAttribute
where
    K: ToString,
    V: Into<TableAttribute>,
{
    fn from(map: HashMap<K, V>) -> Self {
        TableAttribute::Map(
            map.into_iter()
                .map(|(k, v)| (k.to_string(), v.into()))
                .collect(),
        )
    }
}

impl<K, V> TryFromTableAttr for HashMap<K, V>
where
    K: FromStr + std::hash::Hash + std::cmp::Eq,
    V: TryFromTableAttr,
{
    fn try_from_table_attr(value: TableAttribute) -> Result<Self, ReadConversionError> {
        let TableAttribute::Map(map) = value else {
            return Err(ReadConversionError::ConversionFailed(
                std::any::type_name::<Self>().to_string(),
            ));
        };

        map.into_iter()
            .map(|(k, v)| {
                let k = k.parse().map_err(|_| {
                    ReadConversionError::ConversionFailed(std::any::type_name::<Self>().to_string())
                })?;
                let v = V::try_from_table_attr(v)?;

                Ok((k, v))
            })
            .collect()
    }
}

impl<K, V> From<BTreeMap<K, V>> for TableAttribute
where
    K: ToString,
    V: Into<TableAttribute>,
{
    fn from(map: BTreeMap<K, V>) -> Self {
        TableAttribute::Map(
            map.into_iter()
                .map(|(k, v)| (k.to_string(), v.into()))
                .collect(),
        )
    }
}

impl<K, V> TryFromTableAttr for BTreeMap<K, V>
where
    K: FromStr + std::cmp::Ord,
    V: TryFromTableAttr,
{
    fn try_from_table_attr(value: TableAttribute) -> Result<Self, ReadConversionError> {
        let TableAttribute::Map(map) = value else {
            return Err(ReadConversionError::ConversionFailed(
                std::any::type_name::<Self>().to_string(),
            ));
        };

        map.into_iter()
            .map(|(k, v)| {
                let k = k.parse().map_err(|_| {
                    ReadConversionError::ConversionFailed(std::any::type_name::<Self>().to_string())
                })?;
                let v = V::try_from_table_attr(v)?;

                Ok((k, v))
            })
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestType {
        Number,
        String,
        Bytes,
    }

    impl From<TestType> for TableAttribute {
        fn from(value: TestType) -> Self {
            match value {
                TestType::Number => TableAttribute::Number(42.to_string()),
                TestType::String => TableAttribute::String("fourty two".to_string()),
                TestType::Bytes => TableAttribute::Bytes(b"101010".to_vec()),
            }
        }
    }

    impl TryFromTableAttr for TestType {
        fn try_from_table_attr(value: TableAttribute) -> Result<Self, ReadConversionError> {
            match value {
                TableAttribute::Number(n) if n == "42" => Ok(Self::Number),
                TableAttribute::String(s) if s == "fourty two" => Ok(Self::String),
                TableAttribute::Bytes(b) if b == b"101010" => Ok(Self::Bytes),
                _ => Err(ReadConversionError::ConversionFailed("".to_string())),
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    enum MapKeys {
        A,
        B,
        C,
    }

    impl std::fmt::Display for MapKeys {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let c = match self {
                MapKeys::A => "A",
                MapKeys::B => "B",
                MapKeys::C => "C",
            };

            write!(f, "{c}")
        }
    }

    impl FromStr for MapKeys {
        type Err = ();

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "A" => Ok(MapKeys::A),
                "B" => Ok(MapKeys::B),
                "C" => Ok(MapKeys::C),
                _ => Err(()),
            }
        }
    }

    #[test]
    fn test_to_and_from_list() {
        let test_vec = vec![
            TestType::Number,
            TestType::Number,
            TestType::String,
            TestType::Bytes,
        ];

        let table_attribute = TableAttribute::from(test_vec.clone());

        // Assert that we convert to the correct variant.
        assert!(matches!(&table_attribute, TableAttribute::List(x) if x.len() == test_vec.len()));

        let original = Vec::<TestType>::try_from_table_attr(table_attribute).unwrap();

        assert_eq!(original, test_vec);
    }

    #[test]
    fn test_string_vec() {
        let test_vec = vec![
            "String0".to_string(),
            "String1".to_string(),
            "String2".to_string(),
        ];

        let table_attribute = TableAttribute::from(test_vec.clone());

        assert!(matches!(
            &table_attribute,
            TableAttribute::StringVec(x)
            if x.len() == test_vec.len()
        ));

        let original = Vec::<String>::try_from_table_attr(table_attribute).unwrap();

        assert_eq!(original, test_vec);
    }

    #[test]
    fn test_number_vec() {
        let test_vec = vec![2, 3, 5, 7, 13];

        let table_attribute = TableAttribute::from(test_vec.clone());

        assert!(matches!(
            &table_attribute,
            TableAttribute::NumberVec(x)
            if x.len() == test_vec.len()
        ));

        let original = Vec::<i32>::try_from_table_attr(table_attribute).unwrap();

        assert_eq!(original, test_vec);
    }

    #[test]
    fn test_bytes_vec() {
        let test_vec: Vec<Vec<u8>> = (0u8..5).map(|i| (i * 10..i * 10 + 10).collect()).collect();

        let table_attribute = TableAttribute::from(test_vec.clone());

        assert!(matches!(
            &table_attribute,
            TableAttribute::ByteVec(x)
            if x.len() == test_vec.len()
        ));

        let original = Vec::<Vec<u8>>::try_from_table_attr(table_attribute).unwrap();

        assert_eq!(original, test_vec);
    }

    #[test]
    fn test_hashmap() {
        let map = [
            (MapKeys::A, "Something in A".to_string()),
            (MapKeys::A, "Something in B".to_string()),
            (MapKeys::A, "Something in C".to_string()),
        ]
        .into_iter()
        .collect::<HashMap<_, _>>();

        let table_attribute = TableAttribute::from(map.clone());

        assert!(matches!(
            &table_attribute,
            TableAttribute::Map(x)
            if x.len() == map.len()
        ));

        let original = HashMap::<MapKeys, String>::try_from_table_attr(table_attribute).unwrap();

        assert_eq!(original, map);
    }

    #[test]
    fn test_btreemap() {
        let map = [
            (MapKeys::A, "Something in A".to_string()),
            (MapKeys::A, "Something in B".to_string()),
            (MapKeys::A, "Something in C".to_string()),
        ]
        .into_iter()
        .collect::<BTreeMap<_, _>>();

        let table_attribute = TableAttribute::from(map.clone());

        assert!(matches!(
            &table_attribute,
            TableAttribute::Map(x)
            if x.len() == map.len()
        ));

        let original = BTreeMap::<MapKeys, String>::try_from_table_attr(table_attribute).unwrap();

        assert_eq!(original, map);
    }
}
