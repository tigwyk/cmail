use crate::error::Result;
use crate::fsutil;
use crate::identity::now_rfc3339;
use serde::{Deserialize, Serialize};
use std::fs;
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
    // v0.3 relay events (spec §3.4): routing decisions and relay traffic
    KeyRoute,
    RelaySet,
    SendRelay,
    Fetch,
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
    // Single atomic append (payload + newline in one write_all) + fsync:
    // concurrent appenders are cmail's normal mode (one process per agent on
    // a shared root), and a torn line would make `tail` — and the fail-closed
    // `was_released` gate — reject the whole log. See final whole-branch review.
    fsutil::append_line(
        &root.join("audit.log"),
        &format!("{}\n", serde_json::to_string(record)?),
    )
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

/// Display-oriented tail: skips malformed lines instead of failing. The
/// fail-closed `was_released` gate keeps using strict `tail`.
pub fn tail_lossy(root: &Path, n: usize) -> Result<Vec<AuditRecord>> {
    let path = root.join("audit.log");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(&path)?;
    let mut records: Vec<AuditRecord> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
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

    #[test]
    fn all_sixteen_event_names_pinned() {
        for (evt, name) in [
            (AuditEvent::Init, "init"),
            (AuditEvent::Send, "send"),
            (AuditEvent::Held, "held"),
            (AuditEvent::Approve, "approve"),
            (AuditEvent::Reject, "reject"),
            (AuditEvent::Read, "read"),
            (AuditEvent::AllowAdd, "allow_add"),
            (AuditEvent::AllowRemove, "allow_remove"),
            (AuditEvent::KeyAdd, "key_add"),
            (AuditEvent::SpoofSuspected, "spoof_suspected"),
            (AuditEvent::Corrupt, "corrupt"),
            (AuditEvent::QuarantineRelease, "quarantine_release"),
            (AuditEvent::KeyRoute, "key_route"),
            (AuditEvent::RelaySet, "relay_set"),
            (AuditEvent::SendRelay, "send_relay"),
            (AuditEvent::Fetch, "fetch"),
        ] {
            let r = AuditRecord::now(evt, "t");
            let s = serde_json::to_string(&r).unwrap();
            assert!(s.contains(&format!("\"event\":\"{name}\"")), "{s}");
        }
    }

    #[test]
    fn tail_lossy_skips_garbage_but_tail_stays_strict() {
        let root = TempDir::new().unwrap();
        append(root.path(), &AuditRecord::now(AuditEvent::Send, "a")).unwrap();
        // Clean 2-good-1-bad construction: good record, one garbage line
        // appended directly, then another good record.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(root.path().join("audit.log"))
            .unwrap();
        use std::io::Write;
        writeln!(f, "{{garbage").unwrap();
        append(root.path(), &AuditRecord::now(AuditEvent::Read, "a")).unwrap();
        assert!(
            tail(root.path(), 10).is_err(),
            "strict tail must reject the whole file"
        );
        let lossy = tail_lossy(root.path(), 10).unwrap();
        assert_eq!(lossy.len(), 2);
        assert_eq!(lossy[1].event, AuditEvent::Read);
    }
}
