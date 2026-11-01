use crate::envelope::{
    Attachment, Envelope, MAX_ATTACHMENTS, MAX_ATTACHMENT_BYTES, MAX_TOTAL_ATTACHMENT_BYTES,
};
use crate::error::{CoreError, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub struct MailStore {
    root: PathBuf,
}

impl MailStore {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    pub fn mailbox(&self, name: &str) -> PathBuf {
        self.root.join("mailboxes").join(name)
    }

    fn sub(&self, name: &str, kind: &str) -> PathBuf {
        self.mailbox(name).join(kind)
    }

    pub fn inbox_dir(&self, name: &str) -> PathBuf {
        self.sub(name, "inbox")
    }

    pub fn archive_dir(&self, name: &str) -> PathBuf {
        self.sub(name, "archive")
    }

    pub fn pending_dir(&self, name: &str) -> PathBuf {
        self.sub(name, "pending")
    }

    pub fn quarantine_dir(&self, name: &str) -> PathBuf {
        self.sub(name, "quarantine")
    }

    pub fn ensure_mailbox(&self, name: &str) -> Result<()> {
        for d in [
            self.inbox_dir(name),
            self.archive_dir(name),
            self.pending_dir(name),
            self.quarantine_dir(name),
        ] {
            fs::create_dir_all(d)?;
        }
        Ok(())
    }

    fn mail_path(dir: &Path, id: &str) -> PathBuf {
        dir.join(format!("{id}.mail"))
    }

    pub fn write_envelope(&self, dir: &Path, env: &Envelope) -> Result<()> {
        fs::create_dir_all(dir)?;
        let path = Self::mail_path(dir, &env.id);
        let tmp = dir.join(format!("{}.tmp", env.id));
        fs::write(&tmp, serde_json::to_string_pretty(env)?)?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn read_raw(&self, dir: &Path, id: &str) -> Result<String> {
        fs::read_to_string(Self::mail_path(dir, id))
            .map_err(|_| CoreError::MessageNotFound(id.to_string()))
    }

    pub fn list_ids(&self, dir: &Path) -> Vec<String> {
        let mut ids = Vec::new();
        if let Ok(entries) = fs::read_dir(dir) {
            for e in entries.flatten() {
                if let Some(ext) = e.path().extension() {
                    if ext == "mail" {
                        if let Some(stem) = e.path().file_stem().and_then(|s| s.to_str()) {
                            ids.push(stem.to_string());
                        }
                    }
                }
            }
        }
        ids.sort();
        ids
    }

    pub fn move_message(&self, from_dir: &Path, to_dir: &Path, id: &str) -> Result<()> {
        fs::create_dir_all(to_dir)?;
        fs::rename(Self::mail_path(from_dir, id), Self::mail_path(to_dir, id))
            .map_err(|_| CoreError::MessageNotFound(id.to_string()))?;
        Ok(())
    }

    pub fn delete_message(&self, dir: &Path, id: &str) -> Result<()> {
        fs::remove_file(Self::mail_path(dir, id))
            .map_err(|_| CoreError::MessageNotFound(id.to_string()))?;
        Ok(())
    }

    pub fn attachments_dir(&self, id: &str) -> PathBuf {
        self.root.join("attachments").join(id)
    }

    pub fn copy_attachments(&self, id: &str, paths: &[PathBuf]) -> Result<Vec<Attachment>> {
        if paths.len() > MAX_ATTACHMENTS {
            return Err(CoreError::LimitExceeded(format!(
                "more than {MAX_ATTACHMENTS} attachments"
            )));
        }
        let dir = self.attachments_dir(id);
        fs::create_dir_all(&dir)?;
        let mut out = Vec::new();
        let mut total: u64 = 0;
        for p in paths {
            let meta = fs::metadata(p).map_err(CoreError::Io)?;
            if meta.len() > MAX_ATTACHMENT_BYTES {
                return Err(CoreError::LimitExceeded(format!(
                    "{} exceeds {} bytes",
                    p.display(),
                    MAX_ATTACHMENT_BYTES
                )));
            }
            total += meta.len();
            if total > MAX_TOTAL_ATTACHMENT_BYTES {
                return Err(CoreError::LimitExceeded(
                    "attachments exceed 25 MiB total".into(),
                ));
            }
            let bytes = fs::read(p)?;
            let filename = safe_filename(p);
            fs::write(dir.join(&filename), &bytes)?;
            out.push(Attachment {
                filename,
                sha256: hex::encode(Sha256::digest(&bytes)),
                size: meta.len(),
            });
        }
        Ok(out)
    }

    pub fn find_pending(&self, id: &str) -> Result<(String, Envelope)> {
        let mailboxes = self.root.join("mailboxes");
        if let Ok(entries) = fs::read_dir(&mailboxes) {
            for e in entries.flatten() {
                let owner = e.file_name().to_string_lossy().to_string();
                let pending = self.pending_dir(&owner);
                if Self::mail_path(&pending, id).exists() {
                    let raw = self.read_raw(&pending, id)?;
                    let env = Envelope::parse(&raw)?;
                    return Ok((owner, env));
                }
            }
        }
        Err(CoreError::MessageNotFound(id.to_string()))
    }
}

fn safe_filename(p: &Path) -> String {
    let raw = p
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "attachment".into());
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "attachment".into()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{build_and_sign, new_id, NewEnvelope};
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    fn env_fixture(id: &str) -> Envelope {
        let key = SigningKey::generate(&mut OsRng);
        let from_key =
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes());
        build_and_sign(
            id,
            &NewEnvelope {
                from: "alice".into(),
                from_key,
                to: "zoe".into(),
                kind: "note".into(),
                subject: "s".into(),
                body: "b".into(),
                attachments: vec![],
                in_reply_to: None,
                created: "2026-11-01T12:00:00Z".into(),
            },
            &key,
        )
        .unwrap()
    }

    #[test]
    fn write_read_list_move_delete() {
        let root = TempDir::new().unwrap();
        let store = MailStore::new(root.path());
        store.ensure_mailbox("zoe").unwrap();
        let inbox = store.inbox_dir("zoe");
        let archive = store.archive_dir("zoe");
        let env = env_fixture(&new_id());
        store.write_envelope(&inbox, &env).unwrap();
        assert_eq!(store.list_ids(&inbox), vec![env.id.clone()]);
        assert_eq!(
            store.read_raw(&inbox, &env.id).unwrap(),
            serde_json::to_string_pretty(&env).unwrap()
        );
        store.move_message(&inbox, &archive, &env.id).unwrap();
        assert!(store.list_ids(&inbox).is_empty());
        assert_eq!(store.list_ids(&archive), vec![env.id.clone()]);
        store.delete_message(&archive, &env.id).unwrap();
        assert!(store.list_ids(&archive).is_empty());
        assert!(store.read_raw(&archive, &env.id).is_err());
    }

    #[test]
    fn find_pending_scans_all_mailboxes() {
        let root = TempDir::new().unwrap();
        let store = MailStore::new(root.path());
        store.ensure_mailbox("alice").unwrap();
        store.ensure_mailbox("zoe").unwrap();
        let env = env_fixture(&new_id());
        store
            .write_envelope(&store.pending_dir("zoe"), &env)
            .unwrap();
        let (owner, found) = store.find_pending(&env.id).unwrap();
        assert_eq!(owner, "zoe");
        assert_eq!(found.id, env.id);
        assert!(store
            .find_pending("ffffffffffffffffffffffffffffffff")
            .is_err());
    }

    #[test]
    fn attachments_hashed_and_limited() {
        let root = TempDir::new().unwrap();
        let store = MailStore::new(root.path());
        let src = root.path().join("hello.txt");
        fs::write(&src, b"hello world").unwrap();
        let atts = store.copy_attachments("id1", &[src.clone()]).unwrap();
        assert_eq!(atts[0].filename, "hello.txt");
        assert_eq!(atts[0].size, 11);
        assert_eq!(atts[0].sha256.len(), 64);
        assert!(store.attachments_dir("id1").join("hello.txt").exists());
        // count limit
        let many: Vec<PathBuf> = (0..9).map(|_| src.clone()).collect();
        assert!(store.copy_attachments("id2", &many).is_err());
    }
}
