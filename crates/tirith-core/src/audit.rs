use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use fs2::FileExt;
use serde::Serialize;

use crate::verdict::Verdict;

/// An audit log entry.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub action: String,
    pub rule_ids: Vec<String>,
    pub command_redacted: String,
    pub bypass_requested: bool,
    pub bypass_honored: bool,
    pub interactive: bool,
    pub policy_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    pub tier_reached: u8,
}

/// Append an entry to the audit log. Never panics or changes verdict on failure.
pub fn log_verdict(
    verdict: &Verdict,
    command: &str,
    log_path: Option<PathBuf>,
    event_id: Option<String>,
) {
    let path = log_path.or_else(default_log_path);
    let path = match path {
        Some(p) => p,
        None => return,
    };

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let entry = AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        action: format!("{:?}", verdict.action),
        rule_ids: verdict
            .findings
            .iter()
            .map(|f| f.rule_id.to_string())
            .collect(),
        command_redacted: redact_command(command),
        bypass_requested: verdict.bypass_requested,
        bypass_honored: verdict.bypass_honored,
        interactive: verdict.interactive_detected,
        policy_path: verdict.policy_path_used.clone(),
        event_id,
        tier_reached: verdict.tier_reached,
    };

    let line = match serde_json::to_string(&entry) {
        Ok(l) => l,
        Err(_) => return,
    };

    // Open, lock, append, fsync, unlock
    let file = OpenOptions::new().create(true).append(true).open(&path);

    let file = match file {
        Ok(f) => f,
        Err(_) => return,
    };

    if file.lock_exclusive().is_err() {
        return;
    }

    let mut writer = std::io::BufWriter::new(&file);
    let _ = writeln!(writer, "{line}");
    let _ = writer.flush();
    let _ = file.sync_all();
    let _ = fs2::FileExt::unlock(&file);
}

fn default_log_path() -> Option<PathBuf> {
    crate::policy::data_dir().map(|d| d.join("log.jsonl"))
}

fn redact_command(cmd: &str) -> String {
    // Redact: keep first 80 chars, replace the rest
    if cmd.len() <= 80 {
        cmd.to_string()
    } else {
        format!("{}[...redacted {} chars]", &cmd[..80], cmd.len() - 80)
    }
}
