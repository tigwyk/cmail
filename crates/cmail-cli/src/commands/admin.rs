use crate::output;
use crate::Cli;
use anyhow::Result;
use cmail_core::service::KeySource;

pub fn allow(cli: &Cli, cmd: AllowCmd) -> Result<()> {
    // Signing commands share the authority seam so the debug/unavailable
    // backend applies here exactly as it does to keyring edits.
    let c = cmail_core::Cmail::open_with_authority(
        &cli.root_path()?,
        crate::commands::authority::authority(cli),
    )?;
    match cmd {
        AllowCmd::Add { name } => {
            c.allow_add(&name)?;
            if cli.json {
                output::print_json(
                    &serde_json::json!({"status": "allowed", "name": name, "scope": "root-wide"}),
                );
            } else {
                println!("allowed {name} (root-wide: every identity on this root)");
            }
        }
        AllowCmd::Remove { name } => {
            c.allow_remove(&name)?;
            if cli.json {
                output::print_json(
                    &serde_json::json!({"status": "removed", "name": name, "scope": "root-wide"}),
                );
            } else {
                println!("removed {name} (root-wide: every identity on this root)");
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
    let c = cmail_core::Cmail::open_with_authority(
        &cli.root_path()?,
        crate::commands::authority::authority(cli),
    )?;
    let recipient = c.approve(id, remember)?;
    if cli.json {
        let mut v = serde_json::json!({"status":"approved","id":id});
        if remember {
            v["recipient"] = serde_json::json!(recipient);
            v["scope"] = serde_json::json!("root-wide");
        }
        output::print_json(&v);
    } else {
        println!("approved {id}");
        if remember {
            println!(
                "remembered {recipient} on the root-wide outbound allowlist (every identity on this root)"
            );
        }
    }
    Ok(())
}

pub fn reject(cli: &Cli, id: &str) -> Result<()> {
    let c = cmail_core::Cmail::open_with_authority(
        &cli.root_path()?,
        crate::commands::authority::authority(cli),
    )?;
    c.reject(id)?;
    if cli.json {
        output::print_json(&serde_json::json!({"status":"rejected","id":id}));
    } else {
        println!("rejected {id}");
    }
    Ok(())
}

pub fn keyring(cli: &Cli, cmd: KeyringCmd) -> Result<()> {
    let c = cmail_core::Cmail::open_with_authority(
        &cli.root_path()?,
        crate::commands::authority::authority(cli),
    )?;
    match cmd {
        KeyringCmd::Add {
            name,
            key_file,
            from_message,
            route,
        } => {
            let source = if let Some(f) = key_file {
                KeySource::KeyFile(f)
            } else if let Some(m) = from_message {
                KeySource::FromMessage(m)
            } else {
                KeySource::LocalIdentity
            };
            c.keyring_add(&name, source)?;
            if let Some(url) = &route {
                c.keyring_route(&name, Some(url))?;
            }
            if cli.json {
                let mut v = serde_json::json!({"status":"trusted","name":name});
                if let Some(url) = route {
                    v["route"] = serde_json::json!(url);
                }
                output::print_json(&v);
            } else {
                match &route {
                    Some(url) => println!("trusted {name} -> {url}"),
                    None => println!("trusted {name}"),
                }
            }
        }
        KeyringCmd::Remove { name } => {
            c.keyring_remove(&name)?;
            if cli.json {
                output::print_json(&serde_json::json!({"status":"removed","name":name}));
            } else {
                println!("removed {name}");
            }
        }
        KeyringCmd::Route { name, url, clear } => {
            // --clear and a url are mutually exclusive (clap); neither is an error
            let url = if clear {
                None
            } else {
                url.as_deref().map(str::to_string)
            };
            if !clear && url.is_none() {
                anyhow::bail!("keyring route needs a url or --clear");
            }
            c.keyring_route(&name, url.as_deref())?;
            if cli.json {
                let mut v = serde_json::json!({"status": if clear { "cleared" } else { "set" }, "name": name});
                if let Some(u) = &url {
                    v["route"] = serde_json::json!(u);
                }
                output::print_json(&v);
            } else {
                match &url {
                    Some(u) => println!("routed {name} -> {u}"),
                    None => println!("route cleared for {name}"),
                }
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
                        "route": e.route,
                    })
                })
                .collect();
            if cli.json {
                output::print_json(&v);
            } else {
                for it in &v {
                    let route = it["route"]
                        .as_str()
                        .map(|u| format!(" -> {u}"))
                        .unwrap_or_default();
                    println!(
                        "{}  {}{}",
                        it["name"].as_str().unwrap_or("?"),
                        it["fingerprint"].as_str().unwrap_or("?"),
                        route
                    );
                }
            }
        }
    }
    Ok(())
}

pub fn relay(cli: &Cli, cmd: RelayCmd) -> Result<()> {
    let c = cmail_core::Cmail::open_with_authority(
        &cli.root_path()?,
        crate::commands::authority::authority(cli),
    )?;
    match cmd {
        RelayCmd::Set { url } => {
            c.relay_set(Some(&url))?;
            if cli.json {
                output::print_json(
                    &serde_json::json!({"status":"set","url":url,"scope":"root-wide"}),
                );
            } else {
                println!("relay set {url} (root-wide: every identity on this root)");
            }
        }
        RelayCmd::Clear => {
            c.relay_set(None)?;
            if cli.json {
                output::print_json(&serde_json::json!({"status":"cleared","scope":"root-wide"}));
            } else {
                println!("relay cleared (root-wide: every identity on this root)");
            }
        }
        RelayCmd::Show => {
            let url = c.relay_url()?;
            if cli.json {
                output::print_json(&serde_json::json!({"url": url, "scope":"root-wide"}));
            } else {
                match url {
                    Some(u) => println!("{u}"),
                    None => println!("<none>"),
                }
                println!("scope: root-wide (every identity on this root)");
            }
        }
    }
    Ok(())
}

pub fn mode(cli: &Cli, cmd: ModeCmd) -> Result<()> {
    let c = cmail_core::Cmail::open_with_authority(
        &cli.root_path()?,
        crate::commands::authority::authority(cli),
    )?;
    let parse_outbound = |raw: &str| -> Result<cmail_core::config::OutboundMode> {
        match raw {
            "gated" => Ok(cmail_core::config::OutboundMode::Gated),
            "open" => Ok(cmail_core::config::OutboundMode::Open),
            other => anyhow::bail!("unknown outbound mode '{other}'; use gated or open"),
        }
    };
    let parse_inbound = |raw: &str| -> Result<cmail_core::config::InboundMode> {
        match raw {
            "permissive" => Ok(cmail_core::config::InboundMode::Permissive),
            "known-only" => Ok(cmail_core::config::InboundMode::KnownOnly),
            other => anyhow::bail!("unknown inbound mode '{other}'; use permissive or known-only"),
        }
    };
    match cmd {
        ModeCmd::Show => {
            let outbound = c.outbound_mode()?;
            let inbound = c.inbound_mode()?;
            if cli.json {
                output::print_json(&serde_json::json!({
                    "outbound": outbound,
                    "inbound": inbound,
                    "scope": "root-wide",
                }));
            } else {
                println!("outbound: {outbound:?}");
                println!("inbound:  {inbound:?}");
                println!("scope: root-wide (every identity on this root)");
            }
        }
        ModeCmd::Outbound { mode } => {
            let mode = parse_outbound(&mode)?;
            c.set_outbound_mode(mode)?;
            if cli.json {
                output::print_json(&serde_json::json!({
                    "status": "set", "mode": "outbound", "value": mode, "scope": "root-wide",
                }));
            } else {
                println!("outbound mode set to {mode:?} (root-wide: every identity on this root)");
            }
        }
        ModeCmd::Inbound { mode } => {
            let mode = parse_inbound(&mode)?;
            c.set_inbound_mode(mode)?;
            if cli.json {
                output::print_json(&serde_json::json!({
                    "status": "set", "mode": "inbound", "value": mode, "scope": "root-wide",
                }));
            } else {
                println!("inbound mode set to {mode:?} (root-wide: every identity on this root)");
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
        route: Option<String>,
    },
    Remove {
        name: String,
    },
    Route {
        name: String,
        url: Option<String>,
        clear: bool,
    },
    List,
}

pub enum RelayCmd {
    Set { url: String },
    Clear,
    Show,
}

pub enum ModeCmd {
    Show,
    Outbound { mode: String },
    Inbound { mode: String },
}

pub enum QuarantineCmd {
    List,
    Show { id: String },
    Release { id: String },
}
