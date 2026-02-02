use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::Action;

#[derive(Debug, Deserialize)]
struct FixtureFile {
    fixture: Vec<Fixture>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Fixture {
    name: String,
    min_milestone: u8,
    input: String,
    context: String,
    #[serde(default = "default_shell")]
    shell: String,
    expected_action: String,
    expected_rules: Vec<String>,
    #[serde(default)]
    raw_bytes: Vec<u8>,
}

fn default_shell() -> String {
    "posix".to_string()
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
}

fn load_fixtures(filename: &str) -> Vec<Fixture> {
    let path = fixtures_dir().join(filename);
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    let file: FixtureFile = toml::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e));
    file.fixture
}

fn run_fixture(fixture: &Fixture) {
    let shell = fixture
        .shell
        .parse::<ShellType>()
        .unwrap_or(ShellType::Posix);

    let scan_context = match fixture.context.as_str() {
        "exec" => ScanContext::Exec,
        "paste" => ScanContext::Paste,
        _ => panic!("Unknown context: {}", fixture.context),
    };

    let raw_bytes = if !fixture.raw_bytes.is_empty() {
        Some(fixture.raw_bytes.clone())
    } else if scan_context == ScanContext::Paste {
        Some(fixture.input.as_bytes().to_vec())
    } else {
        None
    };

    let ctx = AnalysisContext {
        input: fixture.input.clone(),
        shell,
        scan_context,
        raw_bytes,
        interactive: true,
        cwd: None,
    };

    let verdict = engine::analyze(&ctx);

    let expected_action = match fixture.expected_action.as_str() {
        "allow" => Action::Allow,
        "warn" => Action::Warn,
        "block" => Action::Block,
        other => panic!(
            "Unknown expected_action: {} in fixture {}",
            other, fixture.name
        ),
    };

    // Check action
    assert_eq!(
        verdict.action,
        expected_action,
        "Fixture '{}': expected {:?} but got {:?}. Findings: {:?}",
        fixture.name,
        expected_action,
        verdict.action,
        verdict
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>()
    );

    // Check that expected rules are present (if specified)
    if !fixture.expected_rules.is_empty() {
        let found_rules: Vec<String> = verdict
            .findings
            .iter()
            .map(|f| f.rule_id.to_string())
            .collect();

        for expected_rule in &fixture.expected_rules {
            assert!(
                found_rules.contains(expected_rule),
                "Fixture '{}': expected rule '{}' not found. Found rules: {:?}",
                fixture.name,
                expected_rule,
                found_rules
            );
        }
    }
}

#[test]
fn test_hostname_fixtures() {
    let fixtures = load_fixtures("hostname.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} hostname fixtures");
}

#[test]
fn test_path_fixtures() {
    let fixtures = load_fixtures("path.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} path fixtures");
}

#[test]
fn test_transport_fixtures() {
    let fixtures = load_fixtures("transport.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} transport fixtures");
}

#[test]
fn test_terminal_fixtures() {
    let fixtures = load_fixtures("terminal.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} terminal fixtures");
}

#[test]
fn test_command_fixtures() {
    let fixtures = load_fixtures("command.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} command fixtures");
}

#[test]
fn test_ecosystem_fixtures() {
    let fixtures = load_fixtures("ecosystem.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} ecosystem fixtures");
}

#[test]
fn test_environment_fixtures() {
    let fixtures = load_fixtures("environment.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} environment fixtures");
}

#[test]
fn test_clean_fixtures() {
    let fixtures = load_fixtures("clean.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} clean fixtures");
}

#[test]
fn test_shell_weirdness_fixtures() {
    let fixtures = load_fixtures("shell_weirdness.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} shell weirdness fixtures");
}

#[test]
fn test_policy_fixtures() {
    let fixtures = load_fixtures("policy.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} policy fixtures");
}

/// Verify total fixture count across all files.
#[test]
fn test_fixture_count() {
    let files = [
        "hostname.toml",
        "path.toml",
        "transport.toml",
        "terminal.toml",
        "command.toml",
        "ecosystem.toml",
        "environment.toml",
        "clean.toml",
        "shell_weirdness.toml",
        "policy.toml",
    ];

    let total: usize = files.iter().map(|f| load_fixtures(f).len()).sum();
    eprintln!("Total golden fixtures: {total}");
    assert!(
        total >= 200,
        "Expected at least 200 golden fixtures, found {total}"
    );
}

/// Verify Tier 1 regex catches all rule-triggering fixtures.
#[test]
fn test_tier1_coverage() {
    let files = [
        "hostname.toml",
        "path.toml",
        "transport.toml",
        "terminal.toml",
        "command.toml",
        "ecosystem.toml",
    ];

    let mut missed = Vec::new();

    for filename in &files {
        let fixtures = load_fixtures(filename);
        for fixture in &fixtures {
            if fixture.expected_action == "allow" {
                continue;
            }
            let scan_context = match fixture.context.as_str() {
                "exec" => ScanContext::Exec,
                "paste" => ScanContext::Paste,
                _ => continue,
            };

            // For paste context with raw bytes, check byte scan too
            if scan_context == ScanContext::Paste {
                let bytes = if !fixture.raw_bytes.is_empty() {
                    &fixture.raw_bytes
                } else {
                    fixture.input.as_bytes()
                };
                let byte_scan = tirith_core::extract::scan_bytes(bytes);
                let byte_triggered = byte_scan.has_ansi_escapes
                    || byte_scan.has_control_chars
                    || byte_scan.has_bidi_controls
                    || byte_scan.has_zero_width
                    || byte_scan.has_invalid_utf8;

                if byte_triggered {
                    continue; // Byte scan catches it
                }
            }

            let regex_triggered = tirith_core::extract::tier1_scan(&fixture.input, scan_context);

            if !regex_triggered {
                missed.push(format!(
                    "{}:{} (expected {})",
                    filename, fixture.name, fixture.expected_action
                ));
            }
        }
    }

    if !missed.is_empty() {
        panic!(
            "Tier 1 regex missed {} fixtures (security bug!):\n  {}",
            missed.len(),
            missed.join("\n  ")
        );
    }
}

/// Constraint #6: Non-ASCII in paste is only an analysis trigger, never a sole WARN/BLOCK reason.
/// Pasting text that contains only non-ASCII characters (no URLs, no commands) must result in Allow.
#[test]
fn test_non_ascii_paste_not_sole_warn() {
    let non_ascii_inputs = [
        "café au lait",
        "日本語テスト",
        "Ünïcödé",
        "こんにちは世界",
        "مرحبا",
    ];

    for input in &non_ascii_inputs {
        let raw_bytes = input.as_bytes().to_vec();
        let ctx = AnalysisContext {
            input: input.to_string(),
            shell: ShellType::Posix,
            scan_context: ScanContext::Paste,
            raw_bytes: Some(raw_bytes),
            interactive: true,
            cwd: None,
        };
        let verdict = engine::analyze(&ctx);
        assert_eq!(
            verdict.action,
            Action::Allow,
            "Non-ASCII paste '{}' should not produce WARN/BLOCK by itself, got {:?} with findings: {:?}",
            input,
            verdict.action,
            verdict.findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }
}
