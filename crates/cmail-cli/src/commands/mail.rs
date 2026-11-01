use crate::output;
use crate::Cli;
use anyhow::{bail, Context, Result};
use cmail_core::service::{InboxItem, ReadMessage, SendOutcome};
use std::time::Duration;

pub fn print_item(it: &InboxItem) {
    println!(
        "{}  [{}] {:<8} {:<12} {}",
        it.created, it.trust, it.kind, it.from, it.subject
    );
}

pub fn print_read(m: &ReadMessage) {
    println!(
        "from: {} ({}, fingerprint {})",
        m.from, m.trust, m.fingerprint
    );
    println!("subject: {}", m.subject);
    if !m.attachments.is_empty() {
        println!("attachments: {}", m.attachments.join(", "));
    }
    println!();
    println!("{}", m.body);
}

// Mirrors the clap Send variant 1:1 (brief-pinned signature).
#[expect(clippy::too_many_arguments)]
pub fn send(
    cli: &Cli,
    to: &str,
    kind: &str,
    subject: &str,
    body: Option<String>,
    body_file: Option<std::path::PathBuf>,
    attachments: Vec<std::path::PathBuf>,
    reply_to: Option<String>,
) -> Result<()> {
    let body = match (body, body_file) {
        (Some(b), _) => b,
        (None, Some(f)) => {
            std::fs::read_to_string(&f).with_context(|| format!("reading {}", f.display()))?
        }
        (None, None) => bail!("provide --body or --body-file"),
    };
    let c = cmail_core::Cmail::open(&cli.root_path()?)?;
    let out = c.send(
        cli.as_name.as_deref(),
        to,
        kind,
        subject,
        &body,
        &attachments,
        reply_to.as_deref(),
    )?;
    if cli.json {
        output::print_json(&out);
    } else {
        match &out {
            SendOutcome::Sent { id } => println!("sent ({id})"),
            SendOutcome::Held { id, to } => println!(
                "held for approval by {to} ({id}) — ask your human to run: cmail approvals"
            ),
        }
    }
    Ok(())
}

pub fn inbox(cli: &Cli) -> Result<()> {
    let c = cmail_core::Cmail::open(&cli.root_path()?)?;
    let items = c.inbox(cli.as_name.as_deref())?;
    if cli.json {
        output::print_json(&items);
    } else {
        for it in &items {
            print_item(it);
        }
    }
    Ok(())
}

pub fn read(cli: &Cli, id: &str) -> Result<()> {
    let c = cmail_core::Cmail::open(&cli.root_path()?)?;
    let msg = c.read_message(cli.as_name.as_deref(), id)?;
    if cli.json {
        output::print_json(&msg);
    } else {
        print_read(&msg);
    }
    Ok(())
}

pub fn reply(cli: &Cli, id: &str, body: Option<String>, subject: Option<String>) -> Result<()> {
    let c = cmail_core::Cmail::open(&cli.root_path()?)?;
    let out = c.reply(
        cli.as_name.as_deref(),
        id,
        &body.unwrap_or_default(),
        subject.as_deref(),
    )?;
    if cli.json {
        output::print_json(&out);
    } else {
        match &out {
            SendOutcome::Sent { id } => println!("sent ({id})"),
            SendOutcome::Held { id, to } => println!(
                "held for approval by {to} ({id}) — ask your human to run: cmail approvals"
            ),
        }
    }
    Ok(())
}

pub fn wait(cli: &Cli, timeout_secs: u64) -> Result<()> {
    let c = cmail_core::Cmail::open(&cli.root_path()?)?;
    let items = c.wait(cli.as_name.as_deref(), Duration::from_secs(timeout_secs))?;
    if cli.json {
        output::print_json(&items);
    } else {
        for it in &items {
            print_item(it);
        }
    }
    Ok(())
}

pub fn list(cli: &Cli, all: bool) -> Result<()> {
    let c = cmail_core::Cmail::open(&cli.root_path()?)?;
    let items = c.list(cli.as_name.as_deref(), all)?;
    if cli.json {
        output::print_json(&items);
    } else {
        for it in &items {
            print_item(it);
        }
    }
    Ok(())
}
