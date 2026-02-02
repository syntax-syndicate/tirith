/// Safe runner — Unix only.
/// Downloads a script, analyzes it, optionally executes it with user confirmation.
use std::fs;
use std::io::{self, BufRead, Write};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::receipt::Receipt;
use crate::script_analysis;

pub struct RunResult {
    pub receipt: Receipt,
    pub executed: bool,
    pub exit_code: Option<i32>,
}

pub struct RunOptions {
    pub url: String,
    pub no_exec: bool,
    pub interactive: bool,
}

pub fn run(opts: RunOptions) -> Result<RunResult, String> {
    // Check TTY requirement
    if !opts.no_exec && !opts.interactive {
        return Err("tirith run requires an interactive terminal or --no-exec flag".to_string());
    }

    // Download with redirect chain collection
    let mut redirects: Vec<String> = Vec::new();
    let redirect_list = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let redirect_list_clone = redirect_list.clone();

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if let Ok(mut list) = redirect_list_clone.lock() {
                list.push(attempt.url().to_string());
            }
            if attempt.previous().len() >= 10 {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let response = client
        .get(&opts.url)
        .send()
        .map_err(|e| format!("download failed: {e}"))?;

    let final_url = response.url().to_string();
    if let Ok(list) = redirect_list.lock() {
        redirects = list.clone();
    }

    let content = response.bytes().map_err(|e| format!("read body: {e}"))?;

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let sha256 = format!("{:x}", hasher.finalize());

    // Cache
    let cache_dir = crate::policy::data_dir()
        .ok_or("cannot determine data directory")?
        .join("cache");
    fs::create_dir_all(&cache_dir).map_err(|e| format!("create cache: {e}"))?;
    let cached_path = cache_dir.join(&sha256);
    fs::write(&cached_path, &content).map_err(|e| format!("write cache: {e}"))?;

    let content_str = String::from_utf8_lossy(&content);

    // Analyze
    let interpreter = script_analysis::detect_interpreter(&content_str);
    let analysis = script_analysis::analyze(&content_str, interpreter);

    // Detect git repo and branch
    let (git_repo, git_branch) = detect_git_info();

    // Create receipt
    let receipt = Receipt {
        url: opts.url.clone(),
        final_url: Some(final_url),
        redirects,
        sha256: sha256.clone(),
        size: content.len() as u64,
        domains_referenced: analysis.domains_referenced,
        paths_referenced: analysis.paths_referenced,
        analysis_method: "static".to_string(),
        privilege: if analysis.has_sudo {
            "elevated".to_string()
        } else {
            "normal".to_string()
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        cwd: std::env::current_dir()
            .ok()
            .map(|p| p.display().to_string()),
        git_repo,
        git_branch,
    };

    if opts.no_exec {
        receipt.save().map_err(|e| format!("save receipt: {e}"))?;
        return Ok(RunResult {
            receipt,
            executed: false,
            exit_code: None,
        });
    }

    // Show analysis summary
    eprintln!(
        "tirith: downloaded {} bytes (SHA256: {})",
        content.len(),
        &sha256[..12]
    );
    eprintln!("tirith: interpreter: {interpreter}");
    if analysis.has_sudo {
        eprintln!("tirith: WARNING: script uses sudo");
    }
    if analysis.has_eval {
        eprintln!("tirith: WARNING: script uses eval");
    }
    if analysis.has_base64 {
        eprintln!("tirith: WARNING: script uses base64");
    }

    // Confirm from /dev/tty
    let tty = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "cannot open /dev/tty for confirmation")?;

    let mut tty_writer = io::BufWriter::new(&tty);
    write!(tty_writer, "Execute this script? [y/N] ").map_err(|e| format!("tty write: {e}"))?;
    tty_writer.flush().map_err(|e| format!("tty flush: {e}"))?;

    let mut reader = io::BufReader::new(&tty);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| format!("tty read: {e}"))?;

    if !response_line.trim().eq_ignore_ascii_case("y") {
        eprintln!("tirith: execution cancelled");
        receipt.save().map_err(|e| format!("save receipt: {e}"))?;
        return Ok(RunResult {
            receipt,
            executed: false,
            exit_code: None,
        });
    }

    // Execute
    receipt.save().map_err(|e| format!("save receipt: {e}"))?;

    let status = Command::new(interpreter)
        .arg(&cached_path)
        .status()
        .map_err(|e| format!("execute: {e}"))?;

    Ok(RunResult {
        receipt,
        executed: true,
        exit_code: status.code(),
    })
}

/// Detect git repo remote URL and current branch.
fn detect_git_info() -> (Option<String>, Option<String>) {
    let repo = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string());

    let branch = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string());

    (repo, branch)
}
