use std::collections::HashMap;

use cipherstash_client::{
    credentials::{vitur_credentials::ViturToken, Credentials},
    encryption::{compound_indexer::CompoundIndex, Encryption, IndexTerm, Plaintext},
    schema::{column::Index, TableConfig},
};

use crate::{table_entry::TableEntry, DynamoTarget, EncryptedRecord};

pub(crate) fn encrypted_targets<E: EncryptedRecord>(
    target: &E,
    config: &TableConfig,
) -> HashMap<String, Plaintext> {
    target
        .protected_attributes()
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

fn encrypt_indexes<E: EncryptedRecord + DynamoTarget, C: Credentials<Token = ViturToken>>(
    parition_key: &str,
    target: &E,
    term_length: usize,
    attributes: &HashMap<String, String>, // FIXME: Make a type for *encrypted attribute*
    entries: &mut Vec<TableEntry>,
    cipher: &Encryption<C>,
) -> Result<(), Box<dyn std::error::Error>> {
    for index_name in E::protected_indexes().iter() {
        if let Some((attr, index)) = target
            .attribute_for_index(index_name)
            .and_then(|attr| E::index_by_name(index_name).and_then(|index| Some((attr, index))))
        {
            let index_term = cipher.compound_index(
                &CompoundIndex::new(index),
                attr,
                Some(format!("{}#{}", E::type_name(), index_name)),
                term_length,
            )?;

            let terms = match index_term {
                IndexTerm::Binary(x) => vec![x],
                IndexTerm::BinaryVec(x) => x,
                _ => todo!(),
            };

            for (i, term) in terms.into_iter().enumerate() {
                entries.push(TableEntry {
                    pk: parition_key.to_string(),
                    sk: format!("{}#{}#{}", E::type_name(), index_name, i), // TODO: HMAC the sort key, too (users#index_name#pk)
                    term: Some(hex::encode(term)),
                    attributes: attributes.clone(),
                });
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

    encrypt_indexes(
        &partition_key,
        target,
        12, // output term length
        &attributes,
        &mut table_entries,
        cipher,
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
