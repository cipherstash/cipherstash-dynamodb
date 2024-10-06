mod flattened_encrypted_attributes;
mod flattened_protected_attributes;
mod normalized_protected_attributes;
pub(crate) use flattened_protected_attributes::FlattenedProtectedAttributes;
pub(crate) use normalized_protected_attributes::NormalizedProtectedAttributes;
pub(crate) use flattened_encrypted_attributes::FlattenedEncryptedAttributes;

pub(crate) enum ProtectedAttributes {
    Normalized(NormalizedProtectedAttributes),
    Flattened(FlattenedProtectedAttributes),
}
