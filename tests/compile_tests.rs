#[test]
fn ui_tests() {
    let t = trybuild::TestCases::new();

    t.compile_fail("tests/ui/compound-index-missing-field.rs");
    t.compile_fail("tests/ui/compound-index-missing-config.rs");
    t.compile_fail("tests/ui/compound-index-too-many-fields.rs");
    t.compile_fail("tests/ui/index-unsupported.rs");
    t.compile_fail("tests/ui/compound-index-unsupported.rs");

    t.pass("tests/ui/pass.rs");
}
