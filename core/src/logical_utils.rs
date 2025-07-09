use std::fmt::Display;

#[derive(Debug, Clone, PartialEq)]
pub enum Flag {
    /// Always true
    True,
    /// Always false
    False,
    /// If the build system includes this file to be built
    Building(String),
    /// A raw flag like `CONFIG_ENABLE_FEATURE_A`
    Defined(String),
    /// The inverse of a flag, like `!CONFIG_ENABLE_FEATURE_A`
    Not(Box<Flag>),
    /// The logical *AND* conbination of multiple flags
    And(Vec<Flag>),
    /// The logical *OR* conbination of multiple flags
    Or(Vec<Flag>),
    /// If the variables are equal
    Equal(String, String),
}

impl Display for Flag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::True => write!(f, "1"),
            Self::False => write!(f, "0"),
            Self::Building(file) => write!(f, "building(\"{file}\")"),
            Self::Defined(s) => write!(f, "defined(\"{s}\")"),
            Self::Equal(a, b) => write!(f, "({a} == {b})"),
            Self::Not(s) => write!(f, "(not {s})"),
            Self::And(flags) => write!(
                f,
                "({})",
                flags
                    .iter()
                    //.filter(|f| match f {
                    //    Flag::Literal(_) => true,
                    //    Flag::Not(_) => true,
                    //    Flag::And(flags) => flags.is_empty(),
                    //    Flag::Or(flags) => flags.is_empty(),
                    //})
                    .map(|f| f.to_string())
                    .collect::<Vec<_>>()
                    .join(" & ")
            ),
            Self::Or(flags) => write!(
                f,
                "({})",
                flags
                    .iter()
                    //.filter(|f| match f {
                    //    Flag::Literal(_) => true,
                    //    Flag::Not(_) => true,
                    //    Flag::And(flags) => flags.is_empty(),
                    //    Flag::Or(flags) => flags.is_empty(),
                    //})
                    .map(|f| f.to_string())
                    .collect::<Vec<_>>()
                    .join(" | ")
            ),
        }
    }
}

impl Flag {
    pub fn map_building_flags(self, f: impl Fn(String) -> Flag + Copy) -> Self {
        match self {
            Self::Building(file) => f(file),
            Self::Not(flag) => Self::Not(Box::new(flag.map_building_flags(f))),
            Self::And(inner) => Self::And(
                inner
                    .into_iter()
                    .map(|flag| flag.map_building_flags(f))
                    .collect(),
            ),
            Self::Or(inner) => Self::Or(
                inner
                    .into_iter()
                    .map(|flag| flag.map_building_flags(f))
                    .collect(),
            ),
            _ => self,
        }
    }
}
