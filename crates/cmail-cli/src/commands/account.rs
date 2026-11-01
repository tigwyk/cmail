use crate::output;
use crate::Cli;
use anyhow::Result;
use cmail_core::{identity, Config};

#[derive(clap::Subcommand)]
pub enum AccountCommand {
    Init { name: String },
    Whoami,
    Config,
}

pub fn run(cmd: AccountCommand, cli: &Cli) -> Result<()> {
    let root = cli.root_path()?;
    match cmd {
        AccountCommand::Init { name } => {
            let c = cmail_core::Cmail::open(&root)?;
            c.init(&name)?;
            let id = identity::load_identity(&root, &name)?;
            let value = serde_json::json!({
                "status": "ok",
                "identity": name,
                "fingerprint": id.fingerprint(),
            });
            if cli.json {
                output::print_json(&value);
            } else {
                println!("identity '{name}' ready (fingerprint {})", id.fingerprint());
            }
            Ok(())
        }
        AccountCommand::Whoami => {
            let c = cmail_core::Cmail::open(&root)?;
            let me = c.resolve_identity(cli.as_name.as_deref())?;
            // No identity is an error (exit 1) per spec §7 — never a success
            // with an "error" key.
            if cli.json {
                output::print_json(&serde_json::json!({
                    "identity": me,
                    "root": root.display().to_string(),
                }));
            } else {
                println!("identity: {me}");
            }
            Ok(())
        }
        AccountCommand::Config => {
            let cfg = Config::load_or_init(&root)?;
            if cli.json {
                output::print_json(&serde_json::json!({
                    "root": root.display().to_string(),
                    "config_path": Config::path(&root).display().to_string(),
                    "config": cfg,
                }));
            } else {
                println!("root:  {}", root.display());
                println!("config: {}", Config::path(&root).display());
            }
            Ok(())
        }
    }
}
