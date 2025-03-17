use std::fmt::Display;

#[derive(Debug, Clone)]
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

impl Display for Flag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Literal(s) => write!(f, "{s}"),
            Self::Not(s) => write!(f, "(!{s})"),
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
                    .join(" && ")
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
                    .join(" || ")
            ),
        }
    }
}

impl Flag {
    pub fn simplify(self) -> Flag {
        match self {
            Flag::Literal(s) => Flag::Literal(s),
            Flag::Not(inner) => {
                let simplified_inner = Self::simplify(*inner);
                match simplified_inner {
                    Flag::Not(inner_inner) => *inner_inner,
                    other => Flag::Not(Box::new(other)),
                }
            }
            Flag::And(children) => {
                let mut new_children = Vec::new();
                for child in children.into_iter().map(Self::simplify) {
                    if let Flag::And(nested) = child {
                        new_children.extend(nested);
                    } else {
                        new_children.push(child);
                    }
                }
                match new_children.len() {
                    0 => Flag::And(vec![]), // Handle empty case if needed
                    1 => new_children.into_iter().next().unwrap(),
                    _ => Flag::And(new_children),
                }
            }
            Flag::Or(children) => {
                let mut new_children = Vec::new();
                for child in children.into_iter().map(Self::simplify) {
                    if let Flag::Or(nested) = child {
                        new_children.extend(nested);
                    } else {
                        new_children.push(child);
                    }
                }
                match new_children.len() {
                    0 => Flag::Or(vec![]), // Handle empty case if needed
                    1 => new_children.into_iter().next().unwrap(),
                    _ => Flag::Or(new_children),
                }
            }
        }
    }
}
