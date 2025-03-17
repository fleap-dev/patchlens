
#[derive(Debug)]
pub enum Flag {
    /// A raw flag like `CONFIG_ENABLE_FEATURE_A`
    Literal(String),
    /// The inverse of a flag, like `!CONFIG_ENABLE_FEATURE_A`
    Not(Box<Flag>),
    /// The logical *AND* conbination of multiple flags
    And(Vec<Flag>),
    /// The logical *OR* conbination of multiple flags
    Or(Vec<Flag>),
}

