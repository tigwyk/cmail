use crate::error::{CoreError, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Identity {
    pub name: String,
    pub signing: SigningKey,
}

impl Identity {
    pub fn generate(name: &str) -> Result<Self> {
        validate_name(name)?;
        Ok(Self {
            name: name.to_string(),
            signing: SigningKey::generate(&mut OsRng),
        })
    }

    pub fn public_key_b64(&self) -> String {
        B64.encode(self.signing.verifying_key().as_bytes())
    }

    pub fn fingerprint(&self) -> String {
        fingerprint_of(&self.public_key_b64())
    }
}

pub fn fingerprint_of(public_key_b64: &str) -> String {
    let raw = B64.decode(public_key_b64).unwrap_or_default();
    let hash = Sha256::digest(&raw);
    hex::encode(&hash[..8])
}

pub fn validate_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if valid {
        Ok(())
    } else {
        Err(CoreError::InvalidName(name.to_string()))
    }
}

fn identity_dir(root: &Path, name: &str) -> PathBuf {
    root.join("identities").join(name)
}

pub fn identity_exists(root: &Path, name: &str) -> bool {
    identity_dir(root, name).join("key.ed25519").exists()
}

pub fn create_identity(root: &Path, name: &str) -> Result<Identity> {
    if identity_exists(root, name) {
        return load_identity(root, name);
    }
    let id = Identity::generate(name)?;
    let dir = identity_dir(root, name);
    fs::create_dir_all(&dir)?;
    fs::write(dir.join("key.ed25519"), id.signing.as_bytes())?;
    let perms_notice = set_private_perms(&dir.join("key.ed25519"));
    let _ = perms_notice;
    fs::write(
        dir.join("meta.json"),
        json!({"name": name, "created": now_rfc3339()}).to_string(),
    )?;
    Ok(id)
}

pub fn load_identity(root: &Path, name: &str) -> Result<Identity> {
    let key_path = identity_dir(root, name).join("key.ed25519");
    let bytes = fs::read(&key_path).map_err(|_| CoreError::IdentityNotFound(name.to_string()))?;
    if bytes.len() != 32 {
        // Never crash on bad input (spec §7): a truncated key file is realistic
        // under root-sync. Recover by deleting the broken identity and letting
        // init regenerate it.
        return Err(CoreError::Config(format!(
            "corrupt identity key for '{name}' ({} bytes, expected 32); delete ~/.cmail/identities/{name} and re-run cmail init",
            bytes.len()
        )));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&bytes);
    let signing = SigningKey::from_bytes(&b);
    Ok(Identity {
        name: name.to_string(),
        signing,
    })
}

pub fn list_identities(root: &Path) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(entries) = fs::read_dir(root.join("identities")) {
        for e in entries.flatten() {
            if let Ok(n) = e.file_name().into_string() {
                if e.path().join("key.ed25519").exists() {
                    names.push(n);
                }
            }
        }
    }
    names.sort();
    names
}

pub fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

#[cfg(unix)]
fn set_private_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut p = fs::metadata(path)?.permissions();
    p.set_mode(0o600);
    fs::set_permissions(path, p)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_perms(_path: &Path) -> Result<()> {
    Ok(()) // Windows: best effort per spec
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn root() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn name_rules() {
        assert!(validate_name("zoe").is_ok());
        assert!(validate_name("builder-2").is_ok());
        assert!(validate_name("Zoe").is_err());
        assert!(validate_name("").is_err());
        assert!(validate_name("-zoe").is_err());
        assert!(validate_name(&"a".repeat(65)).is_err());
    }

    #[test]
    fn create_is_idempotent_and_loadable() {
        let root = root();
        let created = create_identity(root.path(), "zoe").unwrap();
        let again = create_identity(root.path(), "zoe").unwrap();
        assert_eq!(created.public_key_b64(), again.public_key_b64());
        assert_eq!(created.fingerprint(), again.fingerprint());
        assert_eq!(created.fingerprint().len(), 16);
        assert!(identity_exists(root.path(), "zoe"));
        assert_eq!(list_identities(root.path()), vec!["zoe"]);
    }

    #[test]
    fn load_missing_fails_with_hint() {
        let root = root();
        let err = load_identity(root.path(), "ghost").unwrap_err();
        assert!(err.to_string().contains("cmail init"));
    }

    #[test]
    fn truncated_key_file_errors_cleanly() {
        let root = TempDir::new().unwrap();
        create_identity(root.path(), "zoe").unwrap();
        fs::write(root.path().join("identities/zoe/key.ed25519"), b"short").unwrap();
        let err = load_identity(root.path(), "zoe").unwrap_err();
        assert!(err.to_string().contains("corrupt identity key"));
        assert!(err.to_string().contains("cmail init"));
    }
}
