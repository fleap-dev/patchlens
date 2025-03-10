use tree_sitter::Point;
use std::collections::HashSet;

use crate::presence_condition_of_src_range;

#[macro_export]
macro_rules! assert_presence_condition {
    ($src:expr, $a_row:expr, $a_col:expr, $b_row:expr, $b_col:expr, $expected:expr) => {{
        let range_desc = format!("{}:{}-{}:{}", $a_row, $a_col, $b_row, $b_col);
        let expected_set: HashSet<_> = $expected.into_iter().collect();
        assert_eq!(
            presence_condition_of_src_range($src, Point::new($a_row, $a_col), Point::new($b_row, $b_col)),
            expected_set,
            "Failed to detect presence condition of src range {} of {}",
            range_desc,
            stringify!($src)
        );
    }};
}

const SAMPLE_SRC_1: &str = include_str!("samples/sample_1.c");
const SAMPLE_SRC_2: &str = include_str!("samples/sample_2.c");

#[test]
fn test_ifdef_block() {
    assert_presence_condition!(
        SAMPLE_SRC_1, 13, 0, 13, 41,
        vec![
            "(ANOTHER_FEATURE)".to_owned(),
            "(VERBOSE_FEATURE)".to_owned(),
        ]
    );

    assert_presence_condition!(
        SAMPLE_SRC_1, 10, 0, 10, 34,
        vec![
            "(VERBOSE_FEATURE)".to_owned(),
        ]
    );

    assert_presence_condition!(
        SAMPLE_SRC_1, 0, 0, 0, 18,
        Vec::<String>::new()
    );

    assert_presence_condition!(
        SAMPLE_SRC_1, 26, 0, 30, 21,
        Vec::<String>::new()
    );

    assert_presence_condition!(
        SAMPLE_SRC_1, 10, 0, 13, 41,
        vec!["(VERBOSE_FEATURE)".to_owned()]
    );
}

#[test]
fn test_ifdef_else_block() {
    assert_presence_condition!(
        SAMPLE_SRC_1, 15, 0, 15, 48,
        vec![
            "(!ANOTHER_FEATURE)".to_owned(),
            "(VERBOSE_FEATURE)".to_owned(),
        ]
    );
}

#[test]
fn test_ifndef_block() {
    assert_presence_condition!(
        SAMPLE_SRC_1, 23, 0, 23, 22,
        vec![
            "(VERBOSE_FEATURE)".to_owned(),
            "(!FAST_FEATURE)".to_owned()
        ]
    );
}

#[test]
fn test_ifndef_else_block() {
    assert_presence_condition!(
        SAMPLE_SRC_2, 35, 0, 35, 17,
        vec![
            "(VERBOSE_FEATURE)".to_owned(),
            "(FAST_FEATURE)".to_owned(),
            "(!SLOW_FEATURE)".to_owned(),
            "(TEST_FEATURE)".to_owned(),
        ]
    );
}

