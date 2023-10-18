use std::collections::HashMap;

use cipherstash_client::{
    credentials::{vitur_credentials::ViturToken, Credentials},
    encryption::{Dictionary, Encryption, IndexTerm, Plaintext},
    schema::{
        column::{Index, IndexType, TokenFilter, Tokenizer},
        operator::Operator,
        TableConfig,
    },
};

use crate::{table_entry::TableEntry, EncryptedRecord};

pub(crate) fn index_type_hack(index_type: IndexType) -> IndexType {
    if let IndexType::Match { .. } = index_type {
        IndexType::Match {
            tokenizer: Tokenizer::EdgeNgram {
                min_gram: 3,
                max_gram: 10,
            },
            token_filters: vec![TokenFilter::Downcase],
            include_original: true,
            k: 0,
            m: 0,
        }
    } else {
        index_type
    }
}

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

/// All index settings that support fuzzy matches
pub(crate) fn encrypted_indexes<E: EncryptedRecord>(
    target: &E,
    config: &TableConfig,
) -> HashMap<String, (Plaintext, IndexType)> {
    target
        .attributes()
        .iter()
        .filter_map(|(attr, plaintext)| {
            config
                .get_column(attr)
                .ok()
                .flatten()
                .and_then(|column| column.index_for_operator(&Operator::ILike))
                // Hack the index type
                .and_then(|index| {
                    Some((
                        attr.to_string(),
                        (plaintext.clone(), index_type_hack(index.index_type.clone())),
                    ))
                })
        })
        .collect()
}

pub(crate) async fn encrypt_query<C, D>(
    query: &Plaintext,
    field_name: &str,
    cipher: &Encryption<C>,
    config: &TableConfig,
    dictionary: &D,
) -> Vec<String>
where
    C: Credentials<Token = ViturToken>,
    D: Dictionary,
{
    let index_type = config
        .get_column(field_name)
        .unwrap()
        .and_then(|c| c.index_for_operator(&Operator::ILike))
        .unwrap()
        .index_type
        .clone();

    if let IndexTerm::PostingArrayQuery(terms) = cipher
        .query_with_dictionary(query, &index_type_hack(index_type), field_name, dictionary)
        .await
        .unwrap()
    {
        terms.into_iter().map(hex::encode).collect()
    } else {
        vec![]
    }
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

pub(crate) async fn encrypt<E, C, D>(
    target: &E,
    cipher: &Encryption<C>,
    config: &TableConfig,
    dictionary: &D,
) -> Vec<TableEntry>
where
    E: EncryptedRecord,
    C: Credentials<Token = ViturToken>,
    D: Dictionary,
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

    let partition_key = encrypt_partition_key(&target.partition_key(), cipher);

    let mut table_entries: Vec<TableEntry> = Vec::new();
    // TODO: Make a constructor on TableEntry so the elements don't have to be pub
    table_entries.push(TableEntry {
        pk: partition_key.to_string(),
        sk: E::type_name().to_string(),
        term: None,
        field: None,
        attributes: attributes.clone(),
    });

    // Indexes
    // TODO: Do the indexes first to avoid clones
    for (name, (plaintext, index_type)) in encrypted_indexes(target, config).iter() {
        if let IndexTerm::PostingArray(postings) = cipher
            .index_with_dictionary(plaintext, &index_type, name, &partition_key, dictionary) // TODO: use encrypted partition key
            .await
            .unwrap()
        {
            postings.iter().for_each(|posting| {
                table_entries.push(TableEntry::new_posting(
                    &partition_key,
                    name,
                    posting,
                    attributes.clone(),
                ));
            });
        }
    }

    table_entries
}

pub(crate) fn encrypt_partition_key<C>(
    value: &str,
    cipher: &Encryption<C>,
) -> String
where
    C: Credentials<Token = ViturToken>,
{
    //let plaintext: Plaintext = format!("{type_name}#{value}").into();
    let plaintext: Plaintext = value.to_string().into();
    let index_type = Index::new_unique().index_type;
    if let IndexTerm::Binary(bytes) = cipher.index(&plaintext, &index_type).unwrap() {
        hex::encode(bytes)
    } else {
        // NOTE: This highlights an ergonomic issue with the way indexers currently work.
        // When indexing with a Unique indexer, the return type should also be Binary.
        // Because this is wrapped in an Enum, we can't guarantee that we'll get one!
        unreachable!()
    }
}
