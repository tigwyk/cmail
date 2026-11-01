use crate::output;
use crate::Cli;
use anyhow::Result;
use cmail_core::service::KeySource;

pub fn allow(cli: &Cli, cmd: AllowCmd) -> Result<()> {
    let c = cmail_core::Cmail::open(&cli.root_path()?)?;
    match cmd {
        AllowCmd::Add { name } => {
            c.allow_add(&name)?;
            if cli.json {
                output::print_json(&serde_json::json!({"status": "allowed", "name": name}));
            } else {
                println!("allowed {name}");
            }
        }
        AllowCmd::Remove { name } => {
            c.allow_remove(&name)?;
            if cli.json {
                output::print_json(&serde_json::json!({"status": "removed", "name": name}));
            } else {
                println!("removed {name}");
            }
        }
        AllowCmd::List => {
            let v = c.allow_list()?;
            if cli.json {
                output::print_json(&v);
            } else {
                for n in v {
                    println!("{n}");
                }
            }
        }
    }
    Ok(())
}

pub fn approvals(cli: &Cli) -> Result<()> {
    let c = cmail_core::Cmail::open(&cli.root_path()?)?;
    let v = c.approvals(cli.as_name.as_deref())?;
    if cli.json {
        output::print_json(&v);
    } else {
        for h in &v {
            println!("{}  {} -> {}  {}", h.id, h.from, h.to, h.subject);
        }
    }
    Ok(())
}

pub fn approve(cli: &Cli, id: &str, remember: bool) -> Result<()> {
    let c = cmail_core::Cmail::open(&cli.root_path()?)?;
    c.approve(id, remember)?;
    if cli.json {
        output::print_json(&serde_json::json!({"status":"approved","id":id}));
    } else {
        println!("approved {id}");
    }
    Ok(())
}

pub fn reject(cli: &Cli, id: &str) -> Result<()> {
    let c = cmail_core::Cmail::open(&cli.root_path()?)?;
    c.reject(id)?;
    if cli.json {
        output::print_json(&serde_json::json!({"status":"rejected","id":id}));
    } else {
        println!("rejected {id}");
    }
    Ok(())
}

pub fn keyring(cli: &Cli, cmd: KeyringCmd) -> Result<()> {
    let c = cmail_core::Cmail::open(&cli.root_path()?)?;
    match cmd {
        KeyringCmd::Add {
            name,
            key_file,
            from_message,
        } => {
            let source = if let Some(f) = key_file {
                KeySource::KeyFile(f)
            } else if let Some(m) = from_message {
                KeySource::FromMessage(m)
            } else {
                KeySource::LocalIdentity
            };
            c.keyring_add(&name, source)?;
            if cli.json {
                output::print_json(&serde_json::json!({"status":"trusted","name":name}));
            } else {
                println!("trusted {name}");
            }
        }
        KeyringCmd::List => {
            let entries = c.keyring_list()?;
            let v: Vec<_> = entries
                .into_iter()
                .map(|(name, e)| {
                    serde_json::json!({
                        "name": name,
                        "fingerprint": cmail_core::identity::fingerprint_of(&e.public_key),
                        "first_seen": e.first_seen,
                    })
                })
                .collect();
            if cli.json {
                output::print_json(&v);
            } else {
                for it in &v {
                    println!(
                        "{}  {}",
                        it["name"].as_str().unwrap_or("?"),
                        it["fingerprint"].as_str().unwrap_or("?")
                    );
                }
            }
        }
    }
    Ok(())
}

pub fn quarantine(cli: &Cli, cmd: QuarantineCmd) -> Result<()> {
    let c = cmail_core::Cmail::open(&cli.root_path()?)?;
    match cmd {
        QuarantineCmd::List => {
            let v = c.quarantine_list(cli.as_name.as_deref())?;
            if cli.json {
                output::print_json(&v);
            } else {
                for it in &v {
                    println!("{}  {}  {}", it.id, it.from, it.subject);
                }
            }
        }
        QuarantineCmd::Show { id } => {
            let m = c.quarantine_show(cli.as_name.as_deref(), &id)?;
            if cli.json {
                output::print_json(&m);
            } else {
                println!("{} ({}):\n{}", m.from, m.trust, m.body);
            }
        }
        QuarantineCmd::Release { id } => {
            c.quarantine_release(&id)?;
            if cli.json {
                output::print_json(&serde_json::json!({"status":"released","id":id}));
            } else {
                println!("released {id}");
            }
        }
    }
    Ok(())
}

pub fn audit(cli: &Cli, tail: usize) -> Result<()> {
    let c = cmail_core::Cmail::open(&cli.root_path()?)?;
    let v = c.audit_tail(tail)?;
    if cli.json {
        output::print_json(&v);
    } else {
        for r in &v {
            println!(
                "{}  {:<18} {}",
                r.ts,
                serde_json::to_value(r.event)
                    .unwrap_or_default()
                    .as_str()
                    .unwrap_or("?"),
                r.actor
            );
        }
    }
    Ok(())
}

pub enum AllowCmd {
    Add { name: String },
    Remove { name: String },
    List,
}

pub enum KeyringCmd {
    Add {
        name: String,
        key_file: Option<std::path::PathBuf>,
        from_message: Option<String>,
    },
    List,
}

pub enum QuarantineCmd {
    List,
    Show { id: String },
    Release { id: String },
}
