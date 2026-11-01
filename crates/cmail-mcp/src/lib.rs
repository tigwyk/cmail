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
    let svc = cmail_core::Cmail::open(&root)?;
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
