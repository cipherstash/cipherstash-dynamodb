use std::collections::HashMap;

use cipherstash_client::{
    credentials::{vitur_credentials::ViturToken, Credentials},
    encryption::{Encryption, Plaintext},
    schema::{
        column::{Index, IndexType, Tokenizer},
        ColumnConfig, TableConfig,
    },
};

use crate::{table_entry::TableEntry, CompoundAttribute, EncryptedRecord};

pub(crate) fn encrypted_targets<E: EncryptedRecord>(
    target: &E,
    config: &TableConfig,
) -> HashMap<String, Plaintext> {
    target
        .attributes()
        .iter()
        .filter_map(|(attr, plaintext)| {
            config
                .get_column(attr)
                .ok()
                .flatten()
                .and_then(|_| Some((attr.to_string(), plaintext.clone())))
        })
        .collect()
}

pub fn encrypt_composite_query<C: Credentials<Token = ViturToken>>(
    type_name: &str,
    query: (&Plaintext, &Plaintext, &CompoundAttribute),
    config: &TableConfig,
    cipher: &Encryption<C>,
) -> Result<String, Box<dyn std::error::Error>> {
    let left_plaintext = query.0;
    let right_plaintext = query.1;
    let attribute = query.2;

    match attribute {
        CompoundAttribute::Exact(left, right) => {
            let left_index_type = config
                .get_column(left)?
                .and_then(get_exact_index_from_config)
                .expect("Expected {left} to have a valid exact config");

            let right_index_type = config
                .get_column(right)?
                .and_then(get_exact_index_from_config)
                .expect("Expected {right} to have a valid exact config");

            let term = cipher.compound_index_exact(
                (left_plaintext, left_index_type),
                (right_plaintext, right_index_type),
            )?;

            let field = format!("{type_name}#{left}#{right}#exact");

            // TODO: field should be combined with term when hmacing not here
            let term = format!("{field}#{}", hex::encode(term));

            Ok(term)
        }

        CompoundAttribute::BeginsWith(left, right) => {
            let left_index_type = config
                .get_column(left)?
                .and_then(get_begins_with_index_from_config)
                .expect("Expected {left} to have a valid begins with config");

            let right_index_type = config
                .get_column(right)?
                .and_then(get_exact_index_from_config)
                .expect("Expected {right} to have a valid exact config");

            // Where do all these go?
            let terms = cipher.compound_index_match(
                (left_plaintext, &left_index_type),
                (right_plaintext, &right_index_type),
            )?;

            let field = format!("{type_name}#{left}#{right}#begins-with");
            let term = terms.into_iter().last().map(hex::encode).unwrap();

            // TODO: field should be combined with term when hmacing not here
            let term = format!("{field}#{term}");

            Ok(term)
        }
    }
}

fn get_exact_index_from_config(config: &ColumnConfig) -> Option<&IndexType> {
    config.indexes.iter().find_map(|Index { index_type, .. }| {
        if let IndexType::Unique { .. } = index_type {
            Some(index_type)
        } else {
            None
        }
    })
}

fn get_begins_with_index_from_config(config: &ColumnConfig) -> Option<&IndexType> {
    config.indexes.iter().find_map(|Index { index_type, .. }| {
        if let IndexType::Match {
            // In order to support begins with needs to be edge ngram
            tokenizer: Tokenizer::EdgeNgram { .. },
            ..
        } = index_type
        {
            Some(index_type)
        } else {
            None
        }
    })
}

fn encrypt_beings_with_indexes<E: EncryptedRecord, C: Credentials<Token = ViturToken>>(
    _parition_key: &str,
    _target: &E,
    _config: &TableConfig,
    _cipher: &Encryption<C>,
    _attributes: &HashMap<String, String>,
    _entries: &mut Vec<TableEntry>,
) -> Result<(), Box<dyn std::error::Error>> {
    // fill this in to support typeahead case

    // let plaintext_attributes = target.attributes();
    // let type_name = E::type_name();

    // for (attribute_name, plaintext) in plaintext_attributes.iter() {
    //     if let Some(config) = config.get_column(attribute_name)? {
    //         for Index { index_type, .. } in config.indexes.iter() {
    //             if let IndexType::Match {
    //                 tokenizer: Tokenizer::EdgeNgram { .. },
    //                 ..
    //             } = index_type
    //             {

    //                 let unique = IndexType::unique();

    //                 break;
    //             } else {
    //                 continue;
    //             }
    //         }
    //     }
    //     // let field = format!("{type_name}#{attribute_name}#exact");
    //     // let term = cipher
    //     //     .index(plaintext, &index_type)?
    //     //     .as_binary()
    //     //     .map(hex::encode)
    //     //     .unwrap();

    //     // entries.push(TableEntry {
    //     //     pk: parition_key.to_string(),
    //     //     sk: field.clone(),
    //     //     field: Some(field),
    //     //     term: Some(term),
    //     //     attributes: attributes.clone(),
    //     // });
    // }

    Ok(())
}

fn encrypt_exact_indexes<E: EncryptedRecord, C: Credentials<Token = ViturToken>>(
    parition_key: &str,
    target: &E,
    config: &TableConfig,
    cipher: &Encryption<C>,
    attributes: &HashMap<String, String>,
    entries: &mut Vec<TableEntry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext_attributes = target.attributes();
    let type_name = E::type_name();

    for (attribute_name, plaintext) in plaintext_attributes.iter() {
        if let Some(index_type) = config
            .get_column(attribute_name)?
            .and_then(get_exact_index_from_config)
        {
            let field = format!("{type_name}#{attribute_name}#exact");

            let term = cipher
                .index(plaintext, &index_type)?
                .as_binary()
                .map(hex::encode)
                .unwrap();

            // TODO: combine field and term when hmacing
            let term = format!("{field}#{term}");

            entries.push(TableEntry {
                pk: parition_key.to_string(),
                sk: field.clone(),
                term: Some(term),
                attributes: attributes.clone(),
            });
        }
    }

    Ok(())
}

fn encrypt_composite_indexes<E: EncryptedRecord, C: Credentials<Token = ViturToken>>(
    parition_key: &str,
    target: &E,
    config: &TableConfig,
    cipher: &Encryption<C>,
    attributes: &HashMap<String, String>,
    entries: &mut Vec<TableEntry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext_attributes = target.attributes();
    let type_name = E::type_name();

    // yikes this should probably be split up a little
    for attribute in target.composite_attributes() {
        match attribute {
            CompoundAttribute::Exact(left, right) => {
                let left_index_type = config
                    .get_column(&left)?
                    .and_then(get_exact_index_from_config)
                    .expect("Expected {left} to have a valid exact config");

                let right_index_type = config
                    .get_column(&right)?
                    .and_then(get_exact_index_from_config)
                    .expect("Expected {right} to have a valid exact config");

                let left_plaintext = plaintext_attributes.get(&left).unwrap();
                let right_plaintext = plaintext_attributes.get(&right).unwrap();

                let term = cipher.compound_index_exact(
                    (left_plaintext, left_index_type),
                    (right_plaintext, right_index_type),
                )?;

                let field = format!("{type_name}#{left}#{right}#exact");
                let term = hex::encode(term);

                entries.push(TableEntry {
                    pk: parition_key.to_string(),
                    sk: field.clone(),
                    // TODO: combine field when hmacing
                    term: Some(format!("{field}#{term}")),
                    attributes: attributes.clone(),
                });
            }

            CompoundAttribute::BeginsWith(left, right) => {
                let left_index_type = config
                    .get_column(&left)?
                    .and_then(get_begins_with_index_from_config)
                    .expect("Expected {left} to have a valid begins with config");

                let right_index_type = config
                    .get_column(&right)?
                    .and_then(get_exact_index_from_config)
                    .expect("Expected {left} to have a valid exact config");

                let left_plaintext = plaintext_attributes.get(&left).unwrap();
                let right_plaintext = plaintext_attributes.get(&right).unwrap();

                // Where do all these go?
                let terms = cipher.compound_index_match(
                    (left_plaintext, left_index_type),
                    (right_plaintext, right_index_type),
                )?;

                let field = format!("{type_name}#{left}#{right}#begins-with");

                for (i, term) in terms.into_iter().enumerate() {
                    let term = hex::encode(term);

                    entries.push(TableEntry {
                        pk: parition_key.to_string(),
                        sk: format!("{field}#{i}"),
                        // TODO: combine field when hmacing
                        term: Some(format!("{field}#{term}")),
                        attributes: attributes.clone(),
                    });
                }
            }
        }
    }

    Ok(())
}

pub(crate) async fn decrypt<C>(
    ciphertexts: HashMap<String, String>,
    cipher: &Encryption<C>,
) -> HashMap<String, Plaintext>
where
    C: Credentials<Token = ViturToken>,
{
    let values: Vec<&String> = ciphertexts.values().collect();
    let plaintexts: Vec<Plaintext> = cipher.decrypt(values).await.unwrap();
    ciphertexts
        .into_keys()
        .zip(plaintexts.into_iter())
        .collect()
}

pub(crate) async fn encrypt<E, C>(
    target: &E,
    cipher: &Encryption<C>,
    config: &TableConfig,
) -> Result<Vec<TableEntry>, Box<dyn std::error::Error>>
where
    E: EncryptedRecord,
    C: Credentials<Token = ViturToken>,
{
    let plaintexts = encrypted_targets(target, config);

    // TODO: Maybe use a wrapper type?
    let mut attributes: HashMap<String, String> = Default::default();
    for (name, plaintext) in plaintexts.iter() {
        // TODO: Use the bulk encrypt
        if let Some(ct) = cipher
            .encrypt_single(&plaintext, &format!("{}#{}", E::type_name(), name))
            .await
            .unwrap()
        {
            attributes.insert(name.to_string(), ct);
        }
    }

    let partition_key = encrypt_partition_key(&target.partition_key(), cipher)?;

    let mut table_entries: Vec<TableEntry> = Vec::new();

    // TODO: Make a constructor on TableEntry so the elements don't have to be pub
    table_entries.push(TableEntry {
        pk: partition_key.to_string(),
        sk: E::type_name().to_string(),
        term: None,
        attributes: attributes.clone(),
    });

    encrypt_exact_indexes(
        &partition_key,
        target,
        config,
        cipher,
        &attributes,
        &mut table_entries,
    )?;

    encrypt_beings_with_indexes(
        &partition_key,
        target,
        config,
        cipher,
        &attributes,
        &mut table_entries,
    )?;

    encrypt_composite_indexes(
        &partition_key,
        target,
        config,
        cipher,
        &attributes,
        &mut table_entries,
    )?;

    Ok(table_entries)
}

pub(crate) fn encrypt_partition_key<C>(
    value: &str,
    cipher: &Encryption<C>,
) -> Result<String, Box<dyn std::error::Error>>
where
    C: Credentials<Token = ViturToken>,
{
    let plaintext = Plaintext::Utf8Str(Some(value.to_string()));
    let index_type = Index::new_unique().index_type;

    Ok(cipher
        .index(&plaintext, &index_type)?
        .as_binary()
        .map(hex::encode)
        .unwrap())
}
