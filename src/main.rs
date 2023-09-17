use cryptonamo::{DynamoTarget, EncryptedRecord};

#[derive(DynamoTarget, EncryptedRecord)]
struct Foo {
    #[dynamo(partition_key)]
    name: String
}

fn main() {
    dbg!(Foo::type_name());
    let f = Foo { name: "Dan".to_string() };
    dbg!(f.attributes());
    dbg!(f.partition_key());
}