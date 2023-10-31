use crate::{
    encrypted_table::{Sealed, TableEntry},
    traits::{Cryptonamo, DecryptedRecord, SearchableRecord},
};
use cipherstash_client::{
    credentials::{vitur_credentials::ViturToken, Credentials},
    encryption::{
        compound_indexer::CompoundIndex, Encryption, EncryptionError, IndexTerm, Plaintext,
        TypeParseError,
    },
    schema::column::Index,
};
use std::collections::HashMap;
use thiserror::Error;

const MAX_TERMS_PER_INDEX: usize = 25;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("EncryptionError: {0}")]
    EncryptionError(#[from] EncryptionError),
    #[error("TypeParseError: {0}")]
    TypeParseError(#[from] TypeParseError),
    #[error("{0}")]
    Other(String),
}

pub(crate) fn all_index_keys<E: SearchableRecord + Cryptonamo>() -> Vec<String> {
    E::protected_indexes()
        .iter()
        .flat_map(|index_name| {
            (0..)
                .take(MAX_TERMS_PER_INDEX)
                .map(|i| format!("{}#{}#{}", E::type_name(), index_name, i))
                .collect::<Vec<String>>()
        })
        .collect()
}

fn encrypt_indexes<E, C>(
    parition_key: &str,
    target: &E,
    term_length: usize,
    // FIXME: Make a type for *encrypted attribute*
    attributes: &HashMap<String, String>,
    entries: &mut Vec<TableEntry>,
    cipher: &Encryption<C>,
) -> Result<(), CryptoError>
where
    E: SearchableRecord + Cryptonamo,
    C: Credentials<Token = ViturToken>,
{
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

            for (i, term) in terms.into_iter().enumerate().take(MAX_TERMS_PER_INDEX) {
                entries.push(TableEntry {
                    pk: parition_key.to_string(),
                    sk: format!("{}#{}#{}", E::type_name(), index_name, i), // TODO: HMAC the sort key, too (users#index_name#pk)
                    term: Some(hex::encode(term)),
                    attributes: HashMap::new(), //attributes.clone(), // FIXME
                });
            }
        }
    }

    Ok(())
}

/*pub(crate) async fn decrypt2<'a, T, C>(
    item: Sealed<'a, TableEntry>,
    cipher: &Encryption<C>,
) -> Result<T, CryptoError>
where
    C: Credentials<Token = ViturToken>,
    T: DecryptedRecord,
{

    //let unsealed: Unsealed<TableEntry> =
    //T::from_unsealed(sealed)?;

    unimplemented!()
}*/

/// FIXME: Remove
/*pub(crate) async fn decrypt<C>(
    ciphertexts: HashMap<String, String>,
    cipher: &Encryption<C>,
) -> Result<HashMap<String, Plaintext>, CryptoError>
where
    C: Credentials<Token = ViturToken>,
{
    let values: Vec<&String> = ciphertexts.values().collect();
    let plaintexts: Vec<Plaintext> = cipher.decrypt(values).await?;
    Ok(ciphertexts
        .into_keys()
        .zip(plaintexts.into_iter())
        .collect())
}*/

/*pub(crate) async fn encrypt<E, C>(
    target: &E,
    cipher: &Encryption<C>,
) -> Result<(String, Vec<TableEntry>), CryptoError>
where
    E: SearchableRecord,
    C: Credentials<Token = ViturToken>,
{
    let protected_attributes = target.protected_attributes();

    // FIXME: Handle types other than string
    let plaintext_attributes = target
        .plaintext_attributes()
        .iter()
        .map(|(field, plaintext)| {
            let key = field.to_string();
            // TODO: Use a Plaintext to DynamoType conversion trait
            let value: String = plaintext.to_inner_from_ref()?;
            Ok::<(String, String), TypeParseError>((key, value))
        })
        .collect::<Result<HashMap<String, String>, _>>()?;

    let entries_to_encrypt = protected_attributes
        .into_iter()
        .map(|(name, plaintext)| (name, plaintext, format!("{}#{}", E::type_name(), name)))
        .collect::<Vec<_>>();

    let encrypted = cipher
        .encrypt(
            entries_to_encrypt
                .iter()
                .map(|(_, plaintext, descriptor)| (plaintext, descriptor.as_str())),
        )
        .await?;

    let attributes: HashMap<String, String> = entries_to_encrypt
        .into_iter()
        .map(|(name, _, _)| name)
        .zip(encrypted.into_iter())
        .flat_map(|(name, ct)| ct.map(|ct| (name.to_string(), ct)))
        .collect();

    let partition_key = encrypt_partition_key(&target.partition_key(), cipher)?;

    let mut table_entries: Vec<TableEntry> = Vec::new();

    // TODO: Make a constructor on TableEntry so the elements don't have to be pub
    /*table_entries.push(TableEntry {
        pk: partition_key.to_string(),
        sk: E::type_name().to_string(),
        term: None,
        // Handle the plaintext attributes as well
        attributes: attributes
            .clone()
            .into_iter()
            .chain(plaintext_attributes.into_iter())
            .collect(),
    });*/

    encrypt_indexes(
        &partition_key,
        target,
        12, // output term length
        &attributes,
        &mut table_entries,
        cipher,
    )?;

    Ok((partition_key, table_entries))
}*/

pub(crate) fn encrypt_partition_key<C>(
    value: &str,
    cipher: &Encryption<C>,
) -> Result<String, CryptoError>
where
    C: Credentials<Token = ViturToken>,
{
    let plaintext = Plaintext::Utf8Str(Some(value.to_string()));
    let index_type = Index::new_unique().index_type;

    cipher
        .index(&plaintext, &index_type)?
        .as_binary()
        .map(hex::encode)
        .ok_or_else(|| CryptoError::Other("Encrypting partition key returned invalid value".into()))
}
