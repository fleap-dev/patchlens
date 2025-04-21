use std::fs;
use std::path::PathBuf;

#[test]
fn test_include_preprocessor() {
    let c_file = PathBuf::from("src/test/samples/sample_1.c");
    let c_source = fs::read_to_string(&c_file).unwrap();
    let folder = c_file.parent().unwrap();

    let default_include_dirs = crate::preprocessor::find_platform_default_include_dirs().unwrap();

    let result = crate::preprocessor::expand_include_macros(
        c_source.as_str(),
        folder,
        &default_include_dirs,
    )
    .unwrap();

    assert!(
        result.len() > c_source.len(),
        "the result should be larger than the initial c source"
    );
}
