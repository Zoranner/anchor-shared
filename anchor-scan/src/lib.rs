//! Anchor Guard 文件扫描引擎。

mod extract;
mod matcher;

use std::path::Path;

use anchor_core::ScanRules;
use extract::extract_text;
use matcher::Matcher;

/// 单个文件扫描的结果。扫描只读取文件，不修改源文件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub extraction: ExtractionStatus,
    pub matches: Vec<RuleMatch>,
}

/// 文本是否可由当前版本提取。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractionStatus {
    Extracted,
    Unsupported,
}

/// 命中的策略规则。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    pub rule_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("扫描规则无效：{0}")]
    InvalidRule(String),
    #[error("读取或提取文件失败：{0}")]
    Read(#[from] std::io::Error),
    #[error("Office Open XML 文件无效：{0}")]
    Office(String),
}

/// 扫描一个受支持文件，返回命中的规则；不会改写源文件。
pub fn scan_file(path: &Path, rules: &ScanRules) -> Result<ScanResult, ScanError> {
    let matcher = Matcher::new(&rules.rules)?;
    let Some(text) = extract_text(path)? else {
        return Ok(ScanResult {
            extraction: ExtractionStatus::Unsupported,
            matches: Vec::new(),
        });
    };

    Ok(ScanResult {
        extraction: ExtractionStatus::Extracted,
        matches: matcher.find_matches(&text),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anchor_core::{ScanRule, ScanRuleKind, ScanRules};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn matching_a_text_file_does_not_change_its_contents() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("notes.txt");
        let original = "公开\n机密计划\n";
        fs::write(&path, original).unwrap();
        let rules = ScanRules {
            controlled_dirs: vec![],
            file_types: vec![],
            rules: vec![ScanRule {
                rule_id: "secret".into(),
                kind: ScanRuleKind::Keyword,
                pattern: "机密".into(),
            }],
        };

        let result = scan_file(&path, &rules).unwrap();

        assert_eq!(result.extraction, ExtractionStatus::Extracted);
        assert_eq!(
            result.matches,
            vec![RuleMatch {
                rule_id: "secret".into()
            }]
        );
        assert_eq!(fs::read_to_string(path).unwrap(), original);
    }

    #[test]
    fn regex_rules_match_and_pdf_is_marked_unsupported() {
        let directory = tempdir().unwrap();
        let text_path = directory.path().join("report.csv");
        let pdf_path = directory.path().join("report.pdf");
        fs::write(&text_path, "record-2026-001").unwrap();
        fs::write(&pdf_path, b"%PDF-not-read").unwrap();
        let rules = ScanRules {
            controlled_dirs: vec![],
            file_types: vec![],
            rules: vec![ScanRule {
                rule_id: "record".into(),
                kind: ScanRuleKind::Regex,
                pattern: r"record-\d{4}-\d+".into(),
            }],
        };

        assert_eq!(
            scan_file(&text_path, &rules).unwrap().matches,
            vec![RuleMatch {
                rule_id: "record".into()
            }]
        );
        assert_eq!(
            scan_file(&pdf_path, &rules).unwrap().extraction,
            ExtractionStatus::Unsupported
        );
    }
}
