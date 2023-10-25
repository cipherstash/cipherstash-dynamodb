use crate::{
    column::{Index, IndexType, TokenFilter},
    DatasetConfig, TablePath,
};

#[test]
fn test_unique_index_no_filters() {
    let yml = "
        tables:
          - path: Users
            fields:
              - name: firstName
                in_place: false
                cast_type: utf8-str
                mode: plaintext-duplicate
                indexes:
                  - version: 1
                    kind: unique
    ";

    let config: DatasetConfig = serde_yaml::from_str(yml).expect("Failed to parse yml");

    let indexes = &config
        .get_table(&TablePath::unqualified("Users"))
        .expect("Expected users table to exist")
        .get_column("firstName")
        .expect("Expected firstName column to return Ok")
        .expect("Expected firstName column to exist")
        .indexes;

    assert_eq!(indexes.len(), 1);

    match &indexes[0] {
        Index {
            index_type: IndexType::Unique { token_filters },
            ..
        } => {
            assert_eq!(token_filters.len(), 0);
        }
        _ => {
            panic!("Expected index type to be unique");
        }
    }
}

#[test]
fn test_unique_index_filters() {
    let yml = "
        tables:
          - path: Users
            fields:
              - name: firstName
                in_place: false
                cast_type: utf8-str
                mode: plaintext-duplicate
                indexes:
                  - version: 1
                    kind: unique
                    token_filters:
                        - kind: downcase
    ";

    let config: DatasetConfig = serde_yaml::from_str(yml).expect("Failed to parse yml");

    let indexes = &config
        .get_table(&TablePath::unqualified("Users"))
        .expect("Expected users table to exist")
        .get_column("firstName")
        .expect("Expected firstName column to return Ok")
        .expect("Expected firstName column to exist")
        .indexes;

    assert_eq!(indexes.len(), 1);

    match &indexes[0] {
        Index {
            index_type: IndexType::Unique { token_filters },
            ..
        } => {
            assert_eq!(token_filters.len(), 1);
            assert!(matches!(token_filters[0], TokenFilter::Downcase));
        }
        _ => {
            panic!("Expected index type to be unique");
        }
    }
}
