use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// A receipt for a script that was downloaded and analyzed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub url: String,
    pub final_url: Option<String>,
    pub redirects: Vec<String>,
    pub sha256: String,
    pub size: u64,
    pub domains_referenced: Vec<String>,
    pub paths_referenced: Vec<String>,
    pub analysis_method: String,
    pub privilege: String,
    pub timestamp: String,
    pub cwd: Option<String>,
    pub git_repo: Option<String>,
    pub git_branch: Option<String>,
}

impl Receipt {
    /// Save receipt atomically (temp file + rename).
    pub fn save(&self) -> Result<PathBuf, String> {
        let dir = receipts_dir().ok_or("cannot determine receipts directory")?;
        fs::create_dir_all(&dir).map_err(|e| format!("create dir: {e}"))?;

        let path = dir.join(format!("{}.json", self.sha256));
        let tmp_path = dir.join(format!(".{}.json.tmp", self.sha256));

        let json = serde_json::to_string_pretty(self).map_err(|e| format!("serialize: {e}"))?;

        fs::write(&tmp_path, &json).map_err(|e| format!("write: {e}"))?;
        fs::rename(&tmp_path, &path).map_err(|e| format!("rename: {e}"))?;

        Ok(path)
    }

    /// Load a receipt by SHA256.
    pub fn load(sha256: &str) -> Result<Self, String> {
        let dir = receipts_dir().ok_or("cannot determine receipts directory")?;
        let path = dir.join(format!("{sha256}.json"));
        let content = fs::read_to_string(&path).map_err(|e| format!("read: {e}"))?;
        serde_json::from_str(&content).map_err(|e| format!("parse: {e}"))
    }

    /// List all receipts.
    pub fn list() -> Result<Vec<Self>, String> {
        let dir = receipts_dir().ok_or("cannot determine receipts directory")?;
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut receipts = Vec::new();
        let entries = fs::read_dir(&dir).map_err(|e| format!("read dir: {e}"))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("entry: {e}"))?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json")
                && !path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with('.'))
            {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(receipt) = serde_json::from_str::<Receipt>(&content) {
                        receipts.push(receipt);
                    }
                }
            }
        }

        receipts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(receipts)
    }

    /// Verify a receipt: check if the file at the cached path still matches sha256.
    pub fn verify(&self) -> Result<bool, String> {
        let cache_dir = cache_dir().ok_or("cannot determine cache directory")?;
        let cached = cache_dir.join(&self.sha256);
        if !cached.exists() {
            return Ok(false);
        }

        let content = fs::read(&cached).map_err(|e| format!("read: {e}"))?;
        let hash = sha2_hex(&content);
        Ok(hash == self.sha256)
    }
}

fn receipts_dir() -> Option<PathBuf> {
    crate::policy::data_dir().map(|d| d.join("receipts"))
}

fn cache_dir() -> Option<PathBuf> {
    crate::policy::data_dir().map(|d| d.join("cache"))
}

fn sha2_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
