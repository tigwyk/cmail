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

    /// Message ids are 32 lowercase hex chars. Validating here makes every
    /// id-taking entry point safe against path traversal (`../` in an id can
    /// never reach the filesystem join), per final whole-branch review.
    fn valid_id(id: &str) -> bool {
        id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn mail_path(dir: &Path, id: &str) -> Result<PathBuf> {
        if !Self::valid_id(id) {
            return Err(CoreError::MessageNotFound(id.to_string()));
        }
        Ok(dir.join(format!("{id}.mail")))
    }

    /// Only a genuine `NotFound` means "message absent"; every other io error
    /// (permissions, not-a-directory, ...) is reported honestly as `Io`
    /// instead of being collapsed into `MessageNotFound`.
    fn classify_io_err(id: &str, e: std::io::Error) -> CoreError {
        match e.kind() {
            std::io::ErrorKind::NotFound => CoreError::MessageNotFound(id.to_string()),
            _ => CoreError::Io(e),
        }
    }

    pub fn write_envelope(&self, dir: &Path, env: &Envelope) -> Result<()> {
        fs::create_dir_all(dir)?;
        let path = Self::mail_path(dir, &env.id)?;
        crate::fsutil::write_durable(&path, serde_json::to_string_pretty(env)?.as_bytes())
    }

    pub fn read_raw(&self, dir: &Path, id: &str) -> Result<String> {
        let path = Self::mail_path(dir, id)?;
        fs::read_to_string(&path).map_err(|e| Self::classify_io_err(id, e))
    }

    pub fn list_ids(&self, dir: &Path) -> Vec<String> {
        let mut ids = Vec::new();
        if let Ok(entries) = fs::read_dir(dir) {
            for e in entries.flatten() {
                if !e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    continue;
                }
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
        let from = Self::mail_path(from_dir, id)?;
        let to = Self::mail_path(to_dir, id)?;
        fs::rename(&from, &to).map_err(|e| Self::classify_io_err(id, e))?;
        Ok(())
    }

    pub fn delete_message(&self, dir: &Path, id: &str) -> Result<()> {
        fs::remove_file(Self::mail_path(dir, id)?).map_err(|e| Self::classify_io_err(id, e))?;
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
        match self.copy_attachments_inner(&dir, paths) {
            Ok(out) => Ok(out),
            Err(e) => {
                // Roll back so a failed copy never leaves a half-populated
                // attachments dir behind.
                let _ = fs::remove_dir_all(&dir);
                Err(e)
            }
        }
    }

    fn copy_attachments_inner(&self, dir: &Path, paths: &[PathBuf]) -> Result<Vec<Attachment>> {
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
                if Self::mail_path(&pending, id)
                    .map(|p| p.exists())
                    .unwrap_or(false)
                {
                    let raw = self.read_raw(&pending, id)?;
                    let env = Envelope::parse(&raw)?;
                    return Ok((owner, env));
                }
            }
        }
        Err(CoreError::MessageNotFound(id.to_string()))
    }

    /// Locate a pending message WITHOUT parsing it. A corrupt pending file
    /// (visible in approvals since H5) can't survive `find_pending`'s parse,
    /// but the human must still be able to clear it via reject.
    pub fn find_pending_file(&self, id: &str) -> Option<(String, std::path::PathBuf)> {
        let mailboxes = self.root.join("mailboxes");
        if let Ok(entries) = fs::read_dir(&mailboxes) {
            for e in entries.flatten() {
                let owner = e.file_name().to_string_lossy().to_string();
                let pending = self.pending_dir(&owner);
                if let Ok(path) = Self::mail_path(&pending, id) {
                    if path.exists() {
                        return Some((owner, path));
                    }
                }
            }
        }
        None
    }

    /// Validated `<dir>/<id>.mail` path (32-hex id gate) for existence
    /// probes, so no probe can act as a filesystem oracle for invalid ids.
    pub fn mail_file_path(&self, dir: &Path, id: &str) -> Result<PathBuf> {
        Self::mail_path(dir, id)
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
    fn traversal_ids_never_reach_the_filesystem() {
        let root = TempDir::new().unwrap();
        let store = MailStore::new(root.path());
        let target = root.path().join("secret.mail");
        fs::write(&target, "TOPSECRET").unwrap();
        for evil in [
            "../../secret",
            "../../../secret",
            "..\\..\\secret",
            "not-an-id",
            "",
        ] {
            let err = store
                .read_raw(&store.inbox_dir("zoe"), evil)
                .expect_err("non-hex id must be rejected before any path join");
            assert!(
                matches!(err, crate::error::CoreError::MessageNotFound(_)),
                "{evil}: {err}"
            );
        }
        // and the planted file is still there, unread
        assert_eq!(fs::read_to_string(&target).unwrap(), "TOPSECRET");
    }

    #[test]
    fn attachments_hashed_and_limited() {
        let root = TempDir::new().unwrap();
        let store = MailStore::new(root.path());
        let src = root.path().join("hello.txt");
        fs::write(&src, b"hello world").unwrap();
        let atts = store
            .copy_attachments("id1", std::slice::from_ref(&src))
            .unwrap();
        assert_eq!(atts[0].filename, "hello.txt");
        assert_eq!(atts[0].size, 11);
        assert_eq!(atts[0].sha256.len(), 64);
        assert!(store.attachments_dir("id1").join("hello.txt").exists());
        // count limit
        let many: Vec<PathBuf> = (0..9).map(|_| src.clone()).collect();
        assert!(store.copy_attachments("id2", &many).is_err());
    }

    #[test]
    fn io_errors_are_not_disguised_as_not_found() {
        let root = TempDir::new().unwrap();
        let store = MailStore::new(root.path());
        // Platform note: a FILE where a directory component is expected
        // (`read_to_string("<file>/sub/<id>.mail")`) cannot be used as the io
        // fixture here — Windows reports ERROR_PATH_NOT_FOUND, which Rust maps
        // to ErrorKind::NotFound, i.e. indistinguishable from a genuinely
        // absent message. The cross-platform fixture is a DIRECTORY sitting at
        // the *.mail path itself: reading it fails with PermissionDenied
        // (windows) / IsADirectory (unix) — an honest io error, not NotFound.
        let id = "ab".repeat(16);
        let inbox = store.inbox_dir("zoe");
        fs::create_dir_all(inbox.join(format!("{id}.mail"))).unwrap();
        let err = store.read_raw(&inbox, &id).unwrap_err();
        assert!(matches!(err, crate::error::CoreError::Io(_)), "{err}");
        // genuinely absent -> MessageNotFound
        let err = store
            .read_raw(&inbox, "cd".repeat(16).as_str())
            .unwrap_err();
        assert!(matches!(err, crate::error::CoreError::MessageNotFound(_)));
    }

    #[test]
    fn list_ids_ignores_directories_named_mail() {
        let root = TempDir::new().unwrap();
        let store = MailStore::new(root.path());
        fs::create_dir_all(store.inbox_dir("zoe").join("trap.mail")).unwrap();
        assert!(store.list_ids(&store.inbox_dir("zoe")).is_empty());
    }

    #[test]
    fn copy_attachments_rolls_back_on_limit_trip() {
        let root = TempDir::new().unwrap();
        let store = MailStore::new(root.path());
        let big = root.path().join("big.bin");
        let mut bytes = vec![0u8; 1024];
        bytes[0..8].copy_from_slice(b"payload!"); // compresses poorly; keeps size honest
        fs::write(&big, bytes.repeat(1024)).unwrap(); // 1 MiB

        // 9 files -> COUNT limit (8) trips at the top, before the dir is created
        let many: Vec<PathBuf> = (0..9).map(|_| big.clone()).collect();
        assert!(store.copy_attachments("rollback1", &many).is_err());
        assert!(
            !store.attachments_dir("rollback1").exists(),
            "count overflow must not create the dir at all"
        );
        // 3 x 10 MiB (each at, not over, the per-file limit) -> TOTAL limit
        // (25 MiB) trips mid-copy, after the dir exists and files are written;
        // the half-populated dir must be rolled back.
        fs::write(&big, bytes.repeat(10240)).unwrap(); // exactly MAX_ATTACHMENT_BYTES
        let heavy: Vec<PathBuf> = (0..3).map(|_| big.clone()).collect();
        assert!(store.copy_attachments("rollback2", &heavy).is_err());
        assert!(
            !store.attachments_dir("rollback2").exists(),
            "failed copy must not leave a dir behind"
        );
    }
}
