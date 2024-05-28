use std::path::Path;

macro_rules! run_tests {
    (fail => {$($f:expr),*}, pass => {$($p:expr),*}) => {
        #[test]
        fn ui_tests() {
            let t = trybuild::TestCases::new();
            let base = Path::new("tests");

            $(
                t.compile_fail(base.join($f));
            )*

            $(
                t.pass(base.join($p));
            )*
        }
    }
}

run_tests! {
    fail => {
        "./ui/compound-index-missing-config.rs",
        "./ui/compound-index-missing-field.rs",
        "./ui/compound-index-too-many-fields.rs",
        "./ui/compound-index-unsupported.rs",
        "./ui/index-unsupported.rs",
        "./ui/invalid-field-name.rs",
        "./ui/no-multi-same-index-per-field.rs",
        "./ui/pk-field-no-partition.rs",
        "./ui/pk-field-wrong-partition.rs",
        "./ui/sk-field-no-sort.rs",
        "./ui/sk-field-wrong-sort.rs",
        "./ui/using-pk-instead-of-pk-sk.rs"
    },

    pass => {
        "./ui/pass.rs",
        "./ui/public_api.rs",
        "./ui/pk-field-on-struct.rs",
        "./ui/various-fields.rs"
    }
}
