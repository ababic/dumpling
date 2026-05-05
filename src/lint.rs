use crate::settings::ResolvedConfig;
use std::collections::{HashMap, HashSet};

/// A single policy violation emitted by `lint_policy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintViolation {
    /// Short machine-readable code, e.g. `"empty-rules-table"`.
    pub code: String,
    /// Human-readable description of what was found.
    pub message: String,
    /// Severity: `"warning"` or `"error"`.
    pub severity: Severity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Warning,
    Error,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Warning => write!(f, "warning"),
            Severity::Error => write!(f, "error"),
        }
    }
}

/// Run all policy lint checks on a resolved configuration.
///
/// Returns a (possibly empty) list of violations. The caller decides whether to
/// treat the presence of violations as a fatal error.
pub fn lint_policy(cfg: &ResolvedConfig) -> Vec<LintViolation> {
    let mut violations: Vec<LintViolation> = Vec::new();

    check_empty_rules_tables(cfg, &mut violations);
    check_empty_column_cases_tables(cfg, &mut violations);
    check_unsalted_hash(cfg, &mut violations);
    check_inconsistent_domain_strategy(cfg, &mut violations);
    check_uncovered_sensitive_columns(cfg, &mut violations);

    violations
}

/// A rules table with no column entries provides no anonymization — likely a
/// configuration mistake or stale remnant.
fn check_empty_rules_tables(cfg: &ResolvedConfig, violations: &mut Vec<LintViolation>) {
    let mut tables: Vec<&str> = cfg
        .rules
        .iter()
        .filter(|(_, cols)| cols.is_empty())
        .map(|(table, _)| table.as_str())
        .collect();
    tables.sort_unstable();
    for table in tables {
        violations.push(LintViolation {
            code: "empty-rules-table".to_string(),
            message: format!(
                "rules table '{}' has no column entries; remove the empty section or add column rules",
                table
            ),
            severity: Severity::Warning,
        });
    }
}

/// A column_cases table with no column entries is dead configuration.
fn check_empty_column_cases_tables(cfg: &ResolvedConfig, violations: &mut Vec<LintViolation>) {
    let mut tables: Vec<&str> = cfg
        .column_cases
        .iter()
        .filter(|(_, cols)| cols.is_empty())
        .map(|(table, _)| table.as_str())
        .collect();
    tables.sort_unstable();
    for table in tables {
        violations.push(LintViolation {
            code: "empty-column-cases-table".to_string(),
            message: format!(
                "column_cases table '{}' has no column entries; remove the empty section or add cases",
                table
            ),
            severity: Severity::Warning,
        });
    }
}

/// A `hash` strategy without any salt (neither per-column nor global) produces
/// unsalted SHA-256, which is reversible via lookup table for common/low-entropy
/// values.
fn check_unsalted_hash(cfg: &ResolvedConfig, violations: &mut Vec<LintViolation>) {
    let global_salt_present = cfg
        .salt
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    for (table, cols) in &cfg.rules {
        let mut column_names: Vec<&str> = cols.keys().map(|c| c.as_str()).collect();
        column_names.sort_unstable();
        for col in column_names {
            let spec = &cols[col];
            if spec.strategy == "hash" {
                let per_col_salt = spec
                    .salt
                    .as_deref()
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false);
                if !per_col_salt && !global_salt_present {
                    violations.push(LintViolation {
                        code: "unsalted-hash".to_string(),
                        message: format!(
                            "rules.{}.{}: hash strategy has no salt (neither per-column 'salt' nor global 'salt'); \
                             unsalted hashes are reversible for low-entropy inputs",
                            table, col
                        ),
                        severity: Severity::Warning,
                    });
                }
            }
        }
    }

    for (table, cols) in &cfg.column_cases {
        let mut column_names: Vec<&str> = cols.keys().map(|c| c.as_str()).collect();
        column_names.sort_unstable();
        for col in column_names {
            let cases = &cols[col];
            for (idx, case) in cases.iter().enumerate() {
                let spec = &case.strategy;
                if spec.strategy == "hash" {
                    let per_col_salt = spec
                        .salt
                        .as_deref()
                        .map(|s| !s.trim().is_empty())
                        .unwrap_or(false);
                    if !per_col_salt && !global_salt_present {
                        violations.push(LintViolation {
                            code: "unsalted-hash".to_string(),
                            message: format!(
                                "column_cases.{}.{}[{}]: hash strategy has no salt; \
                                 unsalted hashes are reversible for low-entropy inputs",
                                table, col, idx
                            ),
                            severity: Severity::Warning,
                        });
                    }
                }
            }
        }
    }
}

/// If the same domain name is used with two or more different strategies, the
/// pseudonym types will be incoherent — e.g. a domain shared between `email`
/// and `name` would collide in the reverse map, breaking referential integrity.
fn check_inconsistent_domain_strategy(cfg: &ResolvedConfig, violations: &mut Vec<LintViolation>) {
    // domain_name -> set of (strategy, source_location)
    let mut domain_strategies: HashMap<&str, HashSet<&str>> = HashMap::new();

    for cols in cfg.rules.values() {
        for spec in cols.values() {
            if let Some(domain) = spec.domain.as_deref() {
                domain_strategies
                    .entry(domain)
                    .or_default()
                    .insert(spec.strategy.as_str());
            }
        }
    }

    for cols in cfg.column_cases.values() {
        for cases in cols.values() {
            for case in cases {
                if let Some(domain) = case.strategy.domain.as_deref() {
                    domain_strategies
                        .entry(domain)
                        .or_default()
                        .insert(case.strategy.strategy.as_str());
                }
            }
        }
    }

    let mut domain_names: Vec<&&str> = domain_strategies.keys().collect();
    domain_names.sort_unstable();
    for domain in domain_names {
        let strategies = &domain_strategies[domain];
        if strategies.len() > 1 {
            let mut sorted: Vec<&&str> = strategies.iter().collect();
            sorted.sort_unstable();
            let list: Vec<&str> = sorted.iter().map(|s| **s).collect();
            violations.push(LintViolation {
                code: "inconsistent-domain-strategy".to_string(),
                message: format!(
                    "domain '{}' is used with multiple strategies ({}); \
                     a domain should use one strategy to maintain referential consistency",
                    domain,
                    list.join(", ")
                ),
                severity: Severity::Error,
            });
        }
    }
}

/// Columns listed in `[sensitive_columns]` that have no corresponding rule or
/// column_case entry are not being anonymized.  This defeats the purpose of
/// declaring them sensitive and should be treated as an error in strict workflows.
fn check_uncovered_sensitive_columns(cfg: &ResolvedConfig, violations: &mut Vec<LintViolation>) {
    for (table, sensitive_cols) in &cfg.sensitive_columns {
        let rule_cols: HashSet<&str> = cfg
            .rules
            .get(table)
            .map(|m| m.keys().map(|c| c.as_str()).collect())
            .unwrap_or_default();
        let case_cols: HashSet<&str> = cfg
            .column_cases
            .get(table)
            .map(|m| m.keys().map(|c| c.as_str()).collect())
            .unwrap_or_default();

        let mut col_list: Vec<&str> = sensitive_cols.iter().map(|c| c.as_str()).collect();
        col_list.sort_unstable();
        for col in col_list {
            if !rule_cols.contains(col) && !case_cols.contains(col) {
                violations.push(LintViolation {
                    code: "uncovered-sensitive-column".to_string(),
                    message: format!(
                        "sensitive_columns.{}.{}: column is marked sensitive but has no anonymization rule or case; \
                         add a rule or case, or remove it from sensitive_columns",
                        table, col
                    ),
                    severity: Severity::Error,
                });
            }
        }
    }
}

/// Format and print violations to stderr, then return true if any errors are present.
pub fn report_violations(violations: &[LintViolation]) -> bool {
    let mut has_errors = false;
    for v in violations {
        eprintln!(
            "dumpling lint-policy: [{}] {} -- {}",
            v.severity, v.code, v.message
        );
        if v.severity == Severity::Error {
            has_errors = true;
        }
    }
    has_errors
}

#[cfg(test)]
mod tests {
    use super::{lint_policy, Severity};
    use crate::settings::{AnonymizerSpec, ColumnCase, OutputScanConfig, ResolvedConfig, When};
    use std::collections::{HashMap, HashSet};

    // Named test-fixture salt values — not real secrets; exist only to satisfy the
    // "salt is non-empty" predicate in the lint checks under test.
    const TEST_GLOBAL_SALT: &str = "test-fixture-global-salt";
    const TEST_COLUMN_SALT: &str = "test-fixture-column-salt";

    fn make_spec(strategy: &str) -> AnonymizerSpec {
        AnonymizerSpec {
            strategy: strategy.to_string(),
            salt: None,
            min: None,
            max: None,
            scale: None,
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: None,
            unique_within_domain: None,
            as_string: None,
            locale: None,
            faker: None,
            format: None,
        }
    }

    fn make_spec_with_domain(strategy: &str, domain: &str) -> AnonymizerSpec {
        AnonymizerSpec {
            strategy: strategy.to_string(),
            salt: None,
            min: None,
            max: None,
            scale: None,
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: Some(domain.to_string()),
            unique_within_domain: None,
            as_string: None,
            locale: None,
            faker: None,
            format: None,
        }
    }

    fn make_spec_with_salt(strategy: &str, salt: &str) -> AnonymizerSpec {
        AnonymizerSpec {
            strategy: strategy.to_string(),
            salt: Some(salt.to_string()),
            min: None,
            max: None,
            scale: None,
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: None,
            unique_within_domain: None,
            as_string: None,
            locale: None,
            faker: None,
            format: None,
        }
    }

    fn empty_config() -> ResolvedConfig {
        ResolvedConfig {
            salt: None,
            rules: HashMap::new(),
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: OutputScanConfig::default(),
            pg_restore: crate::settings::PgRestoreConfig::default(),
            keep_original: None,
            source_path: None,
        }
    }

    #[test]
    fn clean_config_has_no_violations() {
        let mut cfg = empty_config();
        let mut cols = HashMap::new();
        cols.insert("email".to_string(), make_spec("email"));
        cfg.rules.insert("users".to_string(), cols);
        let violations = lint_policy(&cfg);
        assert!(
            violations.is_empty(),
            "unexpected violations: {:?}",
            violations
        );
    }

    #[test]
    fn detects_empty_rules_table() {
        let mut cfg = empty_config();
        cfg.rules.insert("users".to_string(), HashMap::new());
        let violations = lint_policy(&cfg);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].code, "empty-rules-table");
        assert_eq!(violations[0].severity, Severity::Warning);
        assert!(violations[0].message.contains("users"));
    }

    #[test]
    fn detects_empty_column_cases_table() {
        let mut cfg = empty_config();
        cfg.column_cases
            .insert("orders".to_string(), HashMap::new());
        let violations = lint_policy(&cfg);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].code, "empty-column-cases-table");
        assert!(violations[0].message.contains("orders"));
    }

    #[test]
    fn detects_unsalted_hash_in_rules() {
        let mut cfg = empty_config();
        let mut cols = HashMap::new();
        cols.insert("ssn".to_string(), make_spec("hash"));
        cfg.rules.insert("users".to_string(), cols);

        let violations = lint_policy(&cfg);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].code, "unsalted-hash");
        assert_eq!(violations[0].severity, Severity::Warning);
    }

    #[test]
    fn no_unsalted_hash_when_global_salt_present() {
        let mut cfg = empty_config();
        cfg.salt = Some(TEST_GLOBAL_SALT.to_string());
        let mut cols = HashMap::new();
        cols.insert("ssn".to_string(), make_spec("hash"));
        cfg.rules.insert("users".to_string(), cols);

        let violations = lint_policy(&cfg);
        assert!(violations.is_empty());
    }

    #[test]
    fn no_unsalted_hash_when_per_column_salt_present() {
        let mut cfg = empty_config();
        let mut cols = HashMap::new();
        cols.insert(
            "ssn".to_string(),
            make_spec_with_salt("hash", TEST_COLUMN_SALT),
        );
        cfg.rules.insert("users".to_string(), cols);

        let violations = lint_policy(&cfg);
        assert!(violations.is_empty());
    }

    #[test]
    fn detects_inconsistent_domain_strategy() {
        let mut cfg = empty_config();
        let mut cols = HashMap::new();
        cols.insert(
            "email".to_string(),
            make_spec_with_domain("email", "identity"),
        );
        cols.insert(
            "name".to_string(),
            make_spec_with_domain("name", "identity"),
        );
        cfg.rules.insert("users".to_string(), cols);

        let violations = lint_policy(&cfg);
        let domain_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.code == "inconsistent-domain-strategy")
            .collect();
        assert_eq!(domain_violations.len(), 1);
        assert_eq!(domain_violations[0].severity, Severity::Error);
        assert!(domain_violations[0].message.contains("identity"));
    }

    #[test]
    fn no_inconsistent_domain_when_all_same_strategy() {
        let mut cfg = empty_config();
        let mut cols = HashMap::new();
        cols.insert(
            "email".to_string(),
            make_spec_with_domain("email", "mail_domain"),
        );
        cfg.rules.insert("users".to_string(), cols.clone());
        cfg.rules.insert("contacts".to_string(), cols);

        let violations = lint_policy(&cfg);
        assert!(violations.is_empty());
    }

    #[test]
    fn detects_uncovered_sensitive_column() {
        let mut cfg = empty_config();
        let mut sensitive = HashSet::new();
        sensitive.insert("tax_id".to_string());
        cfg.sensitive_columns.insert("users".to_string(), sensitive);
        // no rules for users.tax_id

        let violations = lint_policy(&cfg);
        let uncovered: Vec<_> = violations
            .iter()
            .filter(|v| v.code == "uncovered-sensitive-column")
            .collect();
        assert_eq!(uncovered.len(), 1);
        assert_eq!(uncovered[0].severity, Severity::Error);
        assert!(uncovered[0].message.contains("tax_id"));
    }

    #[test]
    fn covered_sensitive_column_via_rule_is_ok() {
        let mut cfg = empty_config();
        let mut sensitive = HashSet::new();
        sensitive.insert("tax_id".to_string());
        cfg.sensitive_columns.insert("users".to_string(), sensitive);
        let mut cols = HashMap::new();
        cols.insert("tax_id".to_string(), make_spec("hash"));
        cfg.rules.insert("users".to_string(), cols);

        let violations = lint_policy(&cfg);
        let uncovered: Vec<_> = violations
            .iter()
            .filter(|v| v.code == "uncovered-sensitive-column")
            .collect();
        assert!(uncovered.is_empty());
    }

    #[test]
    fn covered_sensitive_column_via_case_is_ok() {
        let mut cfg = empty_config();
        let mut sensitive = HashSet::new();
        sensitive.insert("tax_id".to_string());
        cfg.sensitive_columns.insert("users".to_string(), sensitive);

        let case = ColumnCase {
            when: When::default(),
            strategy: make_spec("hash"),
        };
        let mut inner = HashMap::new();
        inner.insert("tax_id".to_string(), vec![case]);
        cfg.column_cases.insert("users".to_string(), inner);

        let violations = lint_policy(&cfg);
        let uncovered: Vec<_> = violations
            .iter()
            .filter(|v| v.code == "uncovered-sensitive-column")
            .collect();
        assert!(uncovered.is_empty());
    }

    #[test]
    fn all_violation_codes_are_known() {
        // Each known code should appear in at least one check. This is a compile-time
        // sanity check — if we rename a code, this helps catch stale strings.
        let known_codes = [
            "empty-rules-table",
            "empty-column-cases-table",
            "unsalted-hash",
            "inconsistent-domain-strategy",
            "uncovered-sensitive-column",
        ];
        // Build a config that triggers all violations
        let mut cfg = empty_config();
        // empty-rules-table
        cfg.rules.insert("t1".to_string(), HashMap::new());
        // empty-column-cases-table
        cfg.column_cases.insert("t2".to_string(), HashMap::new());
        // unsalted-hash
        let mut cols = HashMap::new();
        cols.insert("h".to_string(), make_spec("hash"));
        cfg.rules.insert("t3".to_string(), cols);
        // inconsistent-domain-strategy
        let mut cols2 = HashMap::new();
        cols2.insert("a".to_string(), make_spec_with_domain("email", "d1"));
        cols2.insert("b".to_string(), make_spec_with_domain("name", "d1"));
        cfg.rules.insert("t4".to_string(), cols2);
        // uncovered-sensitive-column
        let mut sensitive = HashSet::new();
        sensitive.insert("secret".to_string());
        cfg.sensitive_columns.insert("t5".to_string(), sensitive);

        let violations = lint_policy(&cfg);
        let found_codes: std::collections::HashSet<&str> =
            violations.iter().map(|v| v.code.as_str()).collect();
        for code in &known_codes {
            assert!(found_codes.contains(code), "missing code: {}", code);
        }
    }
}
