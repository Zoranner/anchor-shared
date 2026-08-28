use aho_corasick::AhoCorasick;
use anchor_core::{ScanRule, ScanRuleKind};
use regex::Regex;

use crate::{RuleMatch, ScanError};

pub struct Matcher {
    rule_ids: Vec<String>,
    keywords: Option<(AhoCorasick, Vec<usize>)>,
    regexes: Vec<(usize, Regex)>,
}

impl Matcher {
    pub fn new(rules: &[ScanRule]) -> Result<Self, ScanError> {
        let mut keyword_patterns = Vec::new();
        let mut keyword_rule_indexes = Vec::new();
        let mut regexes = Vec::new();

        for (index, rule) in rules.iter().enumerate() {
            match rule.kind {
                ScanRuleKind::Keyword => {
                    keyword_patterns.push(rule.pattern.clone());
                    keyword_rule_indexes.push(index);
                }
                ScanRuleKind::Regex => {
                    let regex = Regex::new(&rule.pattern).map_err(|error| {
                        ScanError::InvalidRule(format!("{}: {error}", rule.rule_id))
                    })?;
                    regexes.push((index, regex));
                }
            }
        }

        let keywords = if keyword_patterns.is_empty() {
            None
        } else {
            Some((
                AhoCorasick::new(keyword_patterns)
                    .map_err(|error| ScanError::InvalidRule(error.to_string()))?,
                keyword_rule_indexes,
            ))
        };

        Ok(Self {
            rule_ids: rules.iter().map(|rule| rule.rule_id.clone()).collect(),
            keywords,
            regexes,
        })
    }

    pub fn find_matches(&self, text: &str) -> Vec<RuleMatch> {
        let mut matched = vec![false; self.rule_ids.len()];
        if let Some((keywords, rule_indexes)) = &self.keywords {
            for found in keywords.find_iter(text) {
                matched[rule_indexes[found.pattern().as_usize()]] = true;
            }
        }
        for (index, regex) in &self.regexes {
            if regex.is_match(text) {
                matched[*index] = true;
            }
        }

        self.rule_ids
            .iter()
            .zip(matched)
            .filter(|(_, is_matched)| *is_matched)
            .map(|(rule_id, _)| RuleMatch {
                rule_id: rule_id.clone(),
            })
            .collect()
    }
}
