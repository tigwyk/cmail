use crate::error::Result;
use crate::identity::now_rfc3339;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvent {
    Init,
    Send,
    Held,
    Approve,
    Reject,
    Read,
    AllowAdd,
    AllowRemove,
    KeyAdd,
    SpoofSuspected,
    Corrupt,
    QuarantineRelease,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditRecord {
    pub ts: String,
    pub event: AuditEvent,
    pub actor: String,
    pub msg_id: Option<String>,
    pub counterpart: Option<String>,
    pub outcome: String,
    pub detail: Option<String>,
}

impl AuditRecord {
    pub fn now(event: AuditEvent, actor: &str) -> Self {
        Self {
            ts: now_rfc3339(),
            event,
            actor: actor.to_string(),
            msg_id: None,
            counterpart: None,
            outcome: "ok".to_string(),
            detail: None,
        }
    }

    pub fn msg(mut self, id: &str) -> Self {
        self.msg_id = Some(id.to_string());
        self
    }

    pub fn counterpart(mut self, name: &str) -> Self {
        self.counterpart = Some(name.to_string());
        self
    }

    pub fn outcome(mut self, s: &str) -> Self {
        self.outcome = s.to_string();
        self
    }

    pub fn detail(mut self, s: &str) -> Self {
        self.detail = Some(s.to_string());
        self
    }
}

pub fn append(root: &Path, record: &AuditRecord) -> Result<()> {
    fs::create_dir_all(root)?;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("audit.log"))?;
    writeln!(f, "{}", serde_json::to_string(record)?)?;
    Ok(())
}

pub fn tail(root: &Path, n: usize) -> Result<Vec<AuditRecord>> {
    let path = root.join("audit.log");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path)?;
    let mut records: Vec<AuditRecord> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    if records.len() > n {
        records.drain(..records.len() - n);
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn append_and_tail() {
        let root = TempDir::new().unwrap();
        append(
            root.path(),
            &AuditRecord::now(AuditEvent::Send, "alice")
                .msg("aa")
                .counterpart("zoe"),
        )
        .unwrap();
        append(
            root.path(),
            &AuditRecord::now(AuditEvent::Held, "alice").msg("bb"),
        )
        .unwrap();
        let all = tail(root.path(), 10).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].event, AuditEvent::Send);
        assert_eq!(all[0].counterpart.as_deref(), Some("zoe"));
        let one = tail(root.path(), 1).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].event, AuditEvent::Held);
    }

    #[test]
    fn serde_names_are_snake_case() {
        let r = AuditRecord::now(AuditEvent::SpoofSuspected, "system");
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"spoof_suspected\""));
    }
}
