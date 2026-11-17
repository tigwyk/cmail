pub mod protocol;
pub mod tools;

use anyhow::Result;
use std::io::{BufRead, Write};
use std::path::PathBuf;

pub fn run_server<R: BufRead, W: Write>(
    root: PathBuf,
    as_name: Option<String>,
    reader: R,
    writer: &mut W,
) -> Result<()> {
    run_server_with_authority(
        root,
        as_name,
        reader,
        writer,
        cmail_core::authority::system_authority(),
    )
}

/// [`run_server`] with an explicit authority port. Tests use the in-memory
/// authority so signed policy reads never touch a real credential store.
pub fn run_server_with_authority<R: BufRead, W: Write>(
    root: PathBuf,
    as_name: Option<String>,
    reader: R,
    writer: &mut W,
    authority: std::sync::Arc<dyn cmail_core::authority::Authority>,
) -> Result<()> {
    let svc = cmail_core::Cmail::open_with_authority(&root, authority)?;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = protocol::handle_line(&line, &svc, as_name.as_deref());
        if let Some(resp) = response {
            writeln!(writer, "{}", serde_json::to_string(&resp)?)?;
            writer.flush()?;
        }
    }
    Ok(())
}
