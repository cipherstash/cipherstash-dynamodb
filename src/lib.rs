
mod crypto;
pub mod traits;
mod encrypted_table;
pub use encrypted_table::{EncryptedTable, QueryBuilder};

#[proc_macro_derive(DynamoTarget)] //, attributes(dynamo))]
pub fn derive_dynamo_target(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let dynamo_name = name.to_string().to_lowercase();

    let expanded = quote! {
        use cryptonamo::target::DynamoTarget;

pub use cryptonamo_derive::{Cryptonamo, EncryptedRecord};
