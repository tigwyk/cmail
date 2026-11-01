use crate::error::Result;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Durable replace: write temp in the same dir, fsync, rename over target.
/// For trust-bearing files (keyring.json, config.toml, mail envelopes) whose
/// loss or tear would confuse the fail-closed gates.
pub fn write_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_data()?;
    drop(f);
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Durable append of one line to an append-only file (single write_all + fsync).
pub fn append_line(path: &Path, line: &str) -> Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(line.as_bytes())?;
    f.sync_data()?;
    Ok(())
}
