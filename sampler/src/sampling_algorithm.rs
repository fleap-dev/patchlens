use rand::prelude::*;
use std::collections::HashSet;
use std::fmt::Debug;
use itertools::Itertools;

/// A sampling algorithm: given a slice of option-names, produce
/// an iterator over all chosen configurations (each config is a
/// Vec of enabled option names).
pub trait SamplingAlgorithm: Debug {
    fn sample<'a>(
        &self,
        options: &'a [String],
    ) -> Box<dyn Iterator<Item = Vec<String>> + 'a>;
}

/// 1) Most-enabled-disabled: all on, then none on.
#[derive(Debug)]
pub struct MostEnabledDisabled;
impl SamplingAlgorithm for MostEnabledDisabled {
    fn sample<'a>(
        &self,
        options: &'a [String],
    ) -> Box<dyn Iterator<Item = Vec<String>> + 'a> {
        let all = options.to_vec();
        let none = Vec::new();
        Box::new(vec![all, none].into_iter())
    }
}

/// 2) One-disabled: disable each option in turn.
#[derive(Debug)]
pub struct OneDisabled;
impl SamplingAlgorithm for OneDisabled {
    fn sample<'a>(
        &self,
        options: &'a [String],
    ) -> Box<dyn Iterator<Item = Vec<String>> + 'a> {
        let configs = options
            .iter()
            .map(|disabled| {
                options
                    .iter()
                    .filter(|o| *o != disabled)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        Box::new(configs.into_iter())
    }
}

/// 3) One-enabled: enable each option alone.
#[derive(Debug)]
pub struct OneEnabled;
impl SamplingAlgorithm for OneEnabled {
    fn sample<'a>(
        &self,
        options: &'a [String],
    ) -> Box<dyn Iterator<Item = Vec<String>> + 'a> {
        let configs = options
            .iter()
            .map(|opt| vec![opt.clone()])
            .collect::<Vec<_>>();
        Box::new(configs.into_iter())
    }
}

/// 4) Statement-coverage: each option once, then none.
#[derive(Debug)]
pub struct StatementCoverage;
impl SamplingAlgorithm for StatementCoverage {
    fn sample<'a>(
        &self,
        options: &'a [String],
    ) -> Box<dyn Iterator<Item = Vec<String>> + 'a> {
        let mut configs = options.iter().map(|opt| vec![opt.clone()]).collect::<Vec<_>>();
        configs.push(Vec::new());
        Box::new(configs.into_iter())
    }
}

/// 5) Random sampling: yield `n` distinct random configs.
#[derive(Debug)]
pub struct RandomSampling {
    pub n: usize,
}
impl SamplingAlgorithm for RandomSampling {
    fn sample<'a>(
        &self,
        options: &'a [String],
    ) -> Box<dyn Iterator<Item = Vec<String>> + 'a> {
        Box::new(RandomSampler::new(options, self.n))
    }
}

/// Internal iterator for random sampling.
struct RandomSampler<'a> {
    options: &'a [String],
    n: usize,
    seen: HashSet<Vec<bool>>,
    rng: ThreadRng,
}
impl<'a> RandomSampler<'a> {
    fn new(options: &'a [String], n: usize) -> Self {
        RandomSampler {
            options,
            n,
            seen: HashSet::new(),
            rng: rand::rng(),
        }
    }
}
impl<'a> Iterator for RandomSampler<'a> {
    type Item = Vec<String>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.seen.len() >= self.n {
            return None;
        }
        loop {
            let assignment: Vec<bool> =
                (0..self.options.len()).map(|_| self.rng.random()).collect();
            if self.seen.insert(assignment.clone()) {
                // map trues to enabled option names
                let cfg = self
                    .options
                    .iter()
                    .zip(assignment.iter())
                    .filter_map(|(opt, &on)| if on { Some(opt.clone()) } else { None })
                    .collect();
                return Some(cfg);
            }
        }
    }
}

/// 6–10) t-wise greedy sampler + wrappers.
#[derive(Debug)]
pub struct TWiseGreedy {
    pub t: usize,
    pub default: bool,
}
impl SamplingAlgorithm for TWiseGreedy {
    fn sample<'a>(
        &self,
        options: &'a [String],
    ) -> Box<dyn Iterator<Item = Vec<String>> + 'a> {
        // Build all (subset, assignment) combos.
        // subset: Vec<usize> indices of options; assignment: Vec<bool> of length t.
        let mut combos = Vec::new();
        for subset in (0..options.len()).combinations(self.t) {
            let domains = vec![vec![false, true]; self.t];
            for assignment in domains.into_iter().multi_cartesian_product() {
                combos.push((subset.clone(), assignment));
            }
        }
        let sampler = TWiseGreedySampler {
            options: options.to_vec(),
            default: self.default,
            combos,
        };
        Box::new(sampler)
    }
}

struct TWiseGreedySampler {
    options: Vec<String>,
    default: bool,
    combos: Vec<(Vec<usize>, Vec<bool>)>,
}
impl Iterator for TWiseGreedySampler {
    type Item = Vec<String>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.combos.is_empty() {
            return None;
        }
        // Pop the first remaining combo
        let (subset, assignment) = self.combos.remove(0);
        // Build a full config
        let mut config: Vec<bool> = Vec::with_capacity(self.options.len());
        for idx in 0..self.options.len() {
            if let Some(pos) = subset.iter().position(|&i| i == idx) {
                config.push(assignment[pos]);
            } else {
                config.push(self.default);
            }
        }
        // Remove all combos covered by this config
        self.combos.retain(|(s, a)| {
            !s
                .iter()
                .zip(a.iter())
                .all(|(&opt_idx, &val)| config[opt_idx] == val)
        });
        // Yield enabled names
        let enabled = self
            .options
            .iter()
            .zip(config.iter())
            .filter_map(|(opt, &on)| if on { Some(opt.clone()) } else { None })
            .collect();
        Some(enabled)
    }
}
