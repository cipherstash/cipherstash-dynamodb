use crate::{
    async_map_somes::async_map_somes,
    encrypted_table::TableEntry,
    traits::{ReadConversionError, TableAttribute, WriteConversionError},
    Decryptable,
};
use aws_sdk_dynamodb::{primitives::Blob, types::AttributeValue};
use cipherstash_client::{
    credentials::{service_credentials::ServiceToken, Credentials},
    encryption::{Encryption, Plaintext},
};
use itertools::Itertools;
use std::{borrow::Cow, collections::HashMap, ops::Deref};

use super::{SealError, Unsealed};

// FIXME: Remove this (only used for debugging)
#[derive(Debug)]
// FIXME: Move this to a separate file
/// Wrapped to indicate that the value is encrypted
pub struct SealedTableEntry(pub(super) TableEntry);

pub struct UnsealSpec<'a> {
    pub protected_attributes: Cow<'a, [Cow<'a, str>]>,
    pub plaintext_attributes: Cow<'a, [Cow<'a, str>]>,
}

impl UnsealSpec<'static> {
    pub fn new_for_decryptable<D: Decryptable>() -> Self {
        Self {
            protected_attributes: D::protected_attributes(),
            plaintext_attributes: D::plaintext_attributes(),
        }
    }
}

impl SealedTableEntry {
    pub fn vec_from<O: TryInto<Self>>(
        items: impl IntoIterator<Item = O>,
    ) -> Result<Vec<Self>, <O as TryInto<Self>>::Error> {
        items.into_iter().map(Self::from_inner).collect()
    }

    pub(super) fn from_inner<O: TryInto<Self>>(
        item: O,
    ) -> Result<Self, <O as TryInto<Self>>::Error> {
        item.try_into()
    }

    pub(crate) fn inner(&self) -> &TableEntry {
        &self.0
    }

    pub(crate) fn into_inner(self) -> TableEntry {
        self.0
    }

    /// Unseal a list of [`Sealed`] values in an efficient manner that optimizes for bulk
    /// decryptions
    ///
    /// This should be used over [`Sealed::unseal`] when multiple values need to be unsealed.
    pub(crate) async fn unseal_all(
        items: Vec<SealedTableEntry>,
        spec: UnsealSpec<'_>,
        cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
    ) -> Result<Vec<Unsealed>, SealError> {
        //let items = items.as_ref();

        let UnsealSpec {
            protected_attributes,
            plaintext_attributes,
        } = spec;

        println!(
            "DECRYPT: Unsealing all items, protected_attributes: {:?}",
            protected_attributes
        );

        // FIXME: The following issues remain:
        // 1. The pk and sk are not being added to the unsealed
        // 2. We don't handle the case where protected_attributes is empty
        // 3. We don't handle the case where plaintext_attributes is empty
        // 4. The zipped iterator is misaligned
        // Unsealed item: Unsealed { descriptor: None, protected: {"name": (SmallInt(Some(42)), "/name"), "age": (Utf8Str(Some("value-a")), "/age"), "attrs": (Utf8Str(Some("value-c")), "/attrs")}, unprotected: TableAttributes({"tag": String("sk")}) }
        // 5. (Minor) The Unsealed is not given a descriptor after decryption
        // 6. Ciphertexts are unexpectedly large
        // 7. Determine if pk and sk should be underscored (check the bahaviour in main or tests)

        //let mut plaintext_items: Vec<Vec<Option<&TableAttribute>>> =
        let mut plaintext_items = Vec::with_capacity(items.len());
        let mut decryptable_items = Vec::with_capacity(items.len() * protected_attributes.len());
        let mut decryptable_names: Vec<String> =
            Vec::with_capacity(items.len() * protected_attributes.len());

        for item in items.into_iter() {
            println!("DECRYPT: Unsealing item: {:?}", item);
            let (protected, unprotected) = item
                .into_inner()
                .attributes
                .partition(protected_attributes.as_ref());

            println!("DECRYPT: Unsealing item: {:?}", protected);

            if !protected_attributes.is_empty() {
                let (names, ciphertexts) = protected
                    .denormalize()
                    .into_iter()
                    .map(|(name, attribute)| {
                        // TODO: Its still unclear why these are even here - if we still need it, move it to the normalise function
                        //dbg!(&item.inner().attributes);
                        /*let attribute = attributes.get(match name.deref() {
                            "pk" => "__pk",
                            "sk" => "__sk",
                            _ => name,
                        });*/

                        // FIXME: We need to track the denormalized attr name so we can use that to key into the Unsealed later
                        println!(
                            "DECRYPT: Decrypting protected attribute: {} = {:?}",
                            name, attribute
                        );
                        attribute
                            .as_encrypted_record()
                            .ok_or_else(|| SealError::InvalidCiphertext(name.to_string()))
                            .map(|attr| (name.to_string(), attr))
                    })
                    .collect::<Result<(Vec<_>, Vec<_>), _>>()?;

                // Create a list of all ciphertexts so that they can all be decrypted in one go.
                // The decrypted version of this list will be chunked up and zipped with the plaintext
                // fields once the decryption succeeds.
                decryptable_items.extend(ciphertexts);
                decryptable_names.extend(names);
            }

            let unprotected = unprotected
                .into_iter()
                .map(|(name, attribute)| {
                    /*let attr = match name.deref() {
                        "sk" => "__sk",
                        _ => name,
                    };

                    attributes.get(attr)*/
                    attribute
                })
                .collect::<Vec<TableAttribute>>();

            plaintext_items.push(unprotected);
        }

        println!("----->> BBB {:?}", decryptable_items);

        //let decrypted = async_map_somes(decryptable_items, |items| cipher.decrypt(items)).await?;
        let decrypted = cipher.decrypt(decryptable_items).await?;
        //let mut default_iter =
        //    std::iter::repeat_with::<Plaintext, _>(|| &[]).take(plaintext_items.len());
        //std::iter::repeat_with::<&[Option<Plaintext>], _>(|| &[]).take(plaintext_items.len());

        println!("----->> CCCC");

        /*let mut chunks_exact;
        //let decrypted_iter: &mut dyn Iterator<Item = &[Option<Plaintext>]> =
        let decrypted_iter: &mut dyn Iterator<Item = Plaintext> =
            if protected_attributes.len() > 0 {
                chunks_exact = decrypted.chunks_exact(protected_attributes.len());
                &mut chunks_exact
            } else {
                &mut default_iter
            };*/

        println!("----->> DDDD");

        // TODO: Handle if protected_attributes is empty
        let unsealed = decrypted
            .into_iter()
            .chunks(protected_attributes.len())
            .into_iter()
            .zip(plaintext_items.into_iter())
            .map(|(decrypted, plaintext_items)| {
                let mut unsealed = Unsealed::new();

                //println!("----->> EEEE {:?} {:?}", protected_attributes, decrypted);

                for (name, plaintext) in decryptable_names.iter().zip(decrypted) {
                    println!("DECRYPT: Inserting protected attribute: {}", name);
                    unsealed.add_protected(name.to_string(), plaintext);
                }

                for (name, plaintext) in
                    plaintext_attributes.iter().zip(plaintext_items.into_iter())
                {
                    unsealed.add_unprotected(name.to_string(), plaintext.clone());
                }

                unsealed
            })
            .collect::<Vec<_>>();

        dbg!(&unsealed);
        Ok(unsealed)
    }

    /// Unseal the current value and return it's plaintext representation
    ///
    /// If you need to unseal multiple values at once use [`Sealed::unseal_all`]
    pub(crate) async fn unseal(
        self,
        spec: UnsealSpec<'_>,
        cipher: &Encryption<impl Credentials<Token = ServiceToken>>,
    ) -> Result<Unsealed, SealError> {
        let mut vec = Self::unseal_all(vec![self], spec, cipher).await?;

        if vec.len() != 1 {
            let actual = vec.len();

            return Err(SealError::AssertionFailed(format!(
                "Expected unseal_all to return 1 result but got {actual}"
            )));
        }

        Ok(vec.remove(0))
    }
}

impl TryFrom<HashMap<String, AttributeValue>> for SealedTableEntry {
    type Error = ReadConversionError;

    fn try_from(item: HashMap<String, AttributeValue>) -> Result<Self, Self::Error> {
        // FIXME: pk and sk should be AttributeValue and term
        let pk = item
            .get("pk")
            .ok_or(ReadConversionError::NoSuchAttribute("pk".to_string()))?
            .as_s()
            .map_err(|_| ReadConversionError::InvalidFormat("pk".to_string()))?
            .to_string();

        let sk = item
            .get("sk")
            .ok_or(ReadConversionError::NoSuchAttribute("sk".to_string()))?
            .as_s()
            .map_err(|_| ReadConversionError::InvalidFormat("sk".to_string()))?
            .to_string();

        let mut table_entry = TableEntry::new(pk, sk);

        item.into_iter()
            .filter(|(k, _)| k != "pk" && k != "sk" && k != "term")
            .for_each(|(k, v)| {
                table_entry.add_attribute(&k, v.into());
            });

        Ok(SealedTableEntry(table_entry))
    }
}

// TODO: Test this conversion
impl TryFrom<SealedTableEntry> for HashMap<String, AttributeValue> {
    type Error = WriteConversionError;

    fn try_from(item: SealedTableEntry) -> Result<Self, Self::Error> {
        let mut map = HashMap::new();

        map.insert("pk".to_string(), AttributeValue::S(item.0.pk));
        map.insert("sk".to_string(), AttributeValue::S(item.0.sk));

        if let Some(term) = item.0.term {
            map.insert("term".to_string(), AttributeValue::B(Blob::new(term)));
        }

        item.0.attributes.into_iter().for_each(|(k, v)| {
            // FIXME: Why would "sk" ever be in the attributes?
            map.insert(
                /*match k.as_str() {
                    "sk" => "__sk".to_string(),
                    _ => k,
                },*/
                k,
                v.into(),
            );
        });

        Ok(map)
    }
}
