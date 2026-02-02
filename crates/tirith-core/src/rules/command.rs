use once_cell::sync::Lazy;
use regex::Regex;

use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

static PIPE_TO_INTERPRETER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\|\s*(?:&\s*)?(?:sudo\s+|env\s+|/\S*/?)*(sh|bash|zsh|dash|ksh|python|python3|node|perl|ruby|php|iex|invoke-expression)\b"
    ).unwrap()
});

/// Run command-shape rules.
pub fn check(input: &str, shell: ShellType) -> Vec<Finding> {
    let mut findings = Vec::new();
    let segments = tokenize::tokenize(input, shell);

    // Check for pipe-to-interpreter patterns
    if PIPE_TO_INTERPRETER.is_match(input) {
        check_pipe_to_interpreter(&segments, &mut findings);
    }

    // Check for insecure TLS flags in source commands
    for segment in &segments {
        if let Some(ref cmd) = segment.command {
            let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd).to_lowercase();
            if is_source_command(&cmd_base) {
                let tls_findings =
                    crate::rules::transport::check_insecure_flags(&segment.args, true);
                findings.extend(tls_findings);
            }
        }
    }

    // Check for dotfile overwrites
    check_dotfile_overwrite(&segments, &mut findings);

    // Check for archive extraction to sensitive paths
    check_archive_extract(&segments, &mut findings);

    findings
}

/// Resolve the effective interpreter from a segment.
/// If the command is `sudo`, `env`, or an absolute path to one of them,
/// look at the first non-flag argument to find the real interpreter.
fn resolve_interpreter_name(seg: &tokenize::Segment) -> Option<String> {
    if let Some(ref cmd) = seg.command {
        let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd).to_lowercase();
        if is_interpreter(&cmd_base) {
            return Some(cmd_base);
        }
        // If the command is sudo, env, or a path, check the first non-flag arg
        if cmd_base == "sudo" || cmd_base == "env" {
            for arg in &seg.args {
                let arg_trimmed = arg.trim();
                if arg_trimmed.starts_with('-') {
                    continue;
                }
                let arg_base = arg_trimmed
                    .rsplit('/')
                    .next()
                    .unwrap_or(arg_trimmed)
                    .to_lowercase();
                if is_interpreter(&arg_base) {
                    return Some(arg_base);
                }
                // If it's not an interpreter, it's the actual command (not an interpreter)
                break;
            }
        }
    }
    None
}

fn check_pipe_to_interpreter(segments: &[tokenize::Segment], findings: &mut Vec<Finding>) {
    for (i, seg) in segments.iter().enumerate() {
        if i == 0 {
            continue;
        }
        if let Some(sep) = &seg.preceding_separator {
            if sep == "|" || sep == "|&" {
                if let Some(interpreter) = resolve_interpreter_name(seg) {
                    // Find the source segment
                    if i > 0 {
                        let source = &segments[i - 1];
                        let source_cmd = source.command.as_deref().unwrap_or("unknown").to_string();
                        let source_base = source_cmd
                            .rsplit('/')
                            .next()
                            .unwrap_or(&source_cmd)
                            .to_lowercase();

                        let rule_id = match source_base.as_str() {
                            "curl" => RuleId::CurlPipeShell,
                            "wget" => RuleId::WgetPipeShell,
                            _ => RuleId::PipeToInterpreter,
                        };

                        let display_cmd = seg.command.as_deref().unwrap_or(&interpreter);

                        findings.push(Finding {
                                rule_id,
                                severity: Severity::High,
                                title: format!("Pipe to interpreter: {source_cmd} | {display_cmd}"),
                                description: format!(
                                    "Command pipes output from '{source_base}' directly to interpreter '{interpreter}'. Downloaded content will be executed without inspection."
                                ),
                                evidence: vec![Evidence::CommandPattern {
                                    pattern: "pipe to interpreter".to_string(),
                                    matched: format!("{} | {}", source.raw, seg.raw),
                                }],
                            });
                    }
                }
            }
        }
    }
}

fn check_dotfile_overwrite(segments: &[tokenize::Segment], findings: &mut Vec<Finding>) {
    for segment in segments {
        // Check for redirects to dotfiles
        let raw = &segment.raw;
        if (raw.contains("> ~/.")
            || raw.contains("> $HOME/.")
            || raw.contains(">> ~/.")
            || raw.contains(">> $HOME/."))
            && !raw.contains("> /dev/null")
        {
            findings.push(Finding {
                rule_id: RuleId::DotfileOverwrite,
                severity: Severity::High,
                title: "Dotfile overwrite detected".to_string(),
                description: "Command redirects output to a dotfile in the home directory, which could overwrite shell configuration".to_string(),
                evidence: vec![Evidence::CommandPattern {
                    pattern: "redirect to dotfile".to_string(),
                    matched: raw.clone(),
                }],
            });
        }
    }
}

fn check_archive_extract(segments: &[tokenize::Segment], findings: &mut Vec<Finding>) {
    for segment in segments {
        if let Some(ref cmd) = segment.command {
            let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd).to_lowercase();
            if cmd_base == "tar" || cmd_base == "unzip" || cmd_base == "7z" {
                // Check if extracting to a sensitive directory
                let raw = &segment.raw;
                let sensitive_targets = [
                    "-C /",
                    "-C ~/",
                    "-C $HOME/",
                    "-d /",
                    "-d ~/",
                    "-d $HOME/",
                    "> ~/.",
                    ">> ~/.",
                ];
                for target in &sensitive_targets {
                    if raw.contains(target) {
                        findings.push(Finding {
                            rule_id: RuleId::ArchiveExtract,
                            severity: Severity::Medium,
                            title: "Archive extraction to sensitive path".to_string(),
                            description: format!(
                                "Archive command '{cmd_base}' extracts to a potentially sensitive location"
                            ),
                            evidence: vec![Evidence::CommandPattern {
                                pattern: "archive extract".to_string(),
                                matched: raw.clone(),
                            }],
                        });
                        return;
                    }
                }
            }
        }
    }
}

fn is_source_command(cmd: &str) -> bool {
    matches!(
        cmd,
        "curl"
            | "wget"
            | "fetch"
            | "scp"
            | "rsync"
            | "iwr"
            | "irm"
            | "invoke-webrequest"
            | "invoke-restmethod"
    )
}

fn is_interpreter(cmd: &str) -> bool {
    matches!(
        cmd,
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "python"
            | "python3"
            | "node"
            | "perl"
            | "ruby"
            | "php"
            | "iex"
            | "invoke-expression"
    )
}
