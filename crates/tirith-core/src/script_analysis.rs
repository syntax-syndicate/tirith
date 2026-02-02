use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;

/// Result of static script analysis.
#[derive(Debug, Clone, Serialize)]
pub struct ScriptAnalysis {
    pub domains_referenced: Vec<String>,
    pub paths_referenced: Vec<String>,
    pub has_sudo: bool,
    pub has_eval: bool,
    pub has_base64: bool,
    pub has_curl_wget: bool,
    pub interpreter: String,
}

static DOMAIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)").unwrap()
});

static PATH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:/(?:usr|etc|var|tmp|opt|home|root|bin|sbin|lib|dev)(?:/[\w.-]+)+)").unwrap()
});

/// Perform static analysis on script content.
pub fn analyze(content: &str, interpreter: &str) -> ScriptAnalysis {
    let mut domains = Vec::new();
    for cap in DOMAIN_RE.captures_iter(content) {
        if let Some(m) = cap.get(1) {
            let domain = m.as_str().to_string();
            if !domains.contains(&domain) {
                domains.push(domain);
            }
        }
    }

    let mut paths = Vec::new();
    for mat in PATH_RE.find_iter(content) {
        let path = mat.as_str().to_string();
        if !paths.contains(&path) {
            paths.push(path);
        }
    }

    ScriptAnalysis {
        domains_referenced: domains,
        paths_referenced: paths,
        has_sudo: content.contains("sudo "),
        has_eval: content.contains("eval ") || content.contains("eval("),
        has_base64: content.contains("base64"),
        has_curl_wget: content.contains("curl ") || content.contains("wget "),
        interpreter: interpreter.to_string(),
    }
}

/// Detect interpreter from shebang line.
pub fn detect_interpreter(content: &str) -> &str {
    if let Some(first_line) = content.lines().next() {
        if first_line.starts_with("#!") {
            let shebang = first_line.trim_start_matches("#!");
            let parts: Vec<&str> = shebang.split_whitespace().collect();
            if let Some(prog) = parts.first() {
                let base = prog.rsplit('/').next().unwrap_or(prog);
                match base {
                    "env" => {
                        if let Some(actual) = parts.get(1) {
                            return actual;
                        }
                    }
                    other => return other,
                }
            }
        }
    }
    "sh" // default
}
