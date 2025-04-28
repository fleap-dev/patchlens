use derive_builder::Builder;
use std::fmt::Display;

#[derive(Debug, Clone)]
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
}

impl Display for Flag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::True => write!(f, "1"),
            Self::False => write!(f, "0"),
            Self::Building(file) => write!(f, "building(\"{file}\")"),
            Self::Defined(s) => write!(f, "defined(\"{s}\")"),
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
    pub fn solve<DefinedFn, BuildingFn>(
        &self,
        defined_fn: &mut DefinedFn,
        building_fn: &mut BuildingFn,
    ) -> bool
    where
        DefinedFn: FnMut(&str) -> bool,
        BuildingFn: FnMut(&str) -> bool,
    {
        match self {
            Flag::True => true,
            Flag::False => false,
            Flag::Building(s) => (building_fn)(s.as_str()),
            Flag::Defined(s) => (defined_fn)(s.as_str()),
            Flag::Not(expr) => !expr.solve(defined_fn, building_fn),
            Flag::And(flags) => flags.iter().all(|f| f.solve(defined_fn, building_fn)),
            Flag::Or(flags) => flags.iter().any(|f| f.solve(defined_fn, building_fn)),
        }
    }

    pub fn simplify(self) -> Flag {
        match self {
            Flag::True => Flag::True,
            Flag::False => Flag::False,
            Flag::Building(f) => Flag::Building(f),
            Flag::Defined(s) => Flag::Defined(s),
            Flag::Not(inner) => {
                let simplified_inner = Self::simplify(*inner);
                match simplified_inner {
                    Flag::Not(inner_inner) => *inner_inner,
                    other => Flag::Not(Box::new(other)),
                }
            }
            Flag::And(children) => {
                let mut new_children = Vec::new();
                for child in children
                    .into_iter()
                    .map(Self::simplify)
                    .filter(|c| !matches!(c, Self::True))
                {
                    if let Flag::And(nested) = child {
                        new_children.extend(nested);
                    } else {
                        new_children.push(child);
                    }
                }
                match new_children.len() {
                    0 => Flag::True, // Handle empty case if needed
                    1 => new_children.into_iter().next().unwrap(),
                    _ => Flag::And(new_children),
                }
            }
            Flag::Or(children) => {
                let mut new_children = Vec::new();
                for child in children.into_iter().map(Self::simplify) {
                    if matches!(child, Self::True) {
                        return Flag::True;
                    }
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
