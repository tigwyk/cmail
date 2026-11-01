mod commands;
mod output;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "cmail",
    version,
    about = "store-and-forward mail for AI agents"
)]
pub struct Cli {
    /// Act as this identity
    #[arg(long = "as", global = true)]
    pub as_name: Option<String>,

    /// Machine-readable JSON output
    #[arg(long, global = true)]
    pub json: bool,

    /// Mailbox root (default: $CMAIL_HOME or ~/.cmail)
    #[arg(long, global = true)]
    pub root: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create (or reuse) an identity
    Init {
        #[arg(long)]
        name: String,
    },
    /// Show active identity and root
    Whoami,
    /// Show config and paths
    Config,
    /// Send mail (subject to outbound gate)
    Send {
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "note")]
        kind: String,
        #[arg(long, default_value = "")]
        subject: String,
        #[arg(long)]
        body: Option<String>,
        #[arg(long)]
        body_file: Option<PathBuf>,
        #[arg(long = "attach")]
        attachments: Vec<PathBuf>,
        #[arg(long)]
        reply_to: Option<String>,
    },
    /// List unread mail
    Inbox,
    /// Read a message (marks it read)
    Read { id: String },
    /// Reply to a message
    Reply {
        id: String,
        #[arg(long)]
        body: Option<String>,
        #[arg(long)]
        subject: Option<String>,
    },
    /// Block until new mail arrives
    Wait {
        #[arg(long = "timeout", default_value = "30")]
        timeout_secs: u64,
    },
    /// List inbox (and archive with --all)
    List {
        #[arg(long)]
        all: bool,
    },
    /// Manage the outbound allowlist
    Allow {
        #[command(subcommand)]
        cmd: AllowCommand,
    },
    /// List held outbound mail
    Approvals,
    /// Release held mail (human-only)
    Approve {
        id: String,
        #[arg(long)]
        remember: bool,
    },
    /// Delete held mail (human-only)
    Reject { id: String },
    /// Manage the keyring of known senders (human-only)
    Keyring {
        #[command(subcommand)]
        cmd: KeyringCommand,
    },
    /// Inspect quarantine (human-only)
    Quarantine {
        #[command(subcommand)]
        cmd: QuarantineCommand,
    },
    /// Tail the audit log
    Audit {
        #[arg(long, default_value = "20")]
        tail: usize,
    },
    /// Run the stdio MCP server
    Mcp,
}

#[derive(Subcommand)]
pub enum AllowCommand {
    Add { name: String },
    Remove { name: String },
    List,
}

#[derive(Subcommand)]
pub enum KeyringCommand {
    Add {
        name: String,
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long)]
        from_message: Option<String>,
    },
    List,
}

#[derive(Subcommand)]
pub enum QuarantineCommand {
    List,
    Show { id: String },
    Release { id: String },
}

impl Cli {
    pub fn root_path(&self) -> Result<PathBuf> {
        if let Some(p) = &self.root {
            return Ok(p.clone());
        }
        if let Ok(env) = std::env::var("CMAIL_HOME") {
            if !env.is_empty() {
                return Ok(PathBuf::from(env));
            }
        }
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .context("cannot determine home directory (set CMAIL_HOME)")?;
        Ok(PathBuf::from(home).join(".cmail"))
    }
}

fn main() {
    let cli = Cli::parse();
    let result = match &cli.command {
        Commands::Init { name } => commands::account::run(
            commands::account::AccountCommand::Init { name: name.clone() },
            &cli,
        ),
        Commands::Whoami => commands::account::run(commands::account::AccountCommand::Whoami, &cli),
        Commands::Config => commands::account::run(commands::account::AccountCommand::Config, &cli),
        Commands::Send {
            to,
            kind,
            subject,
            body,
            body_file,
            attachments,
            reply_to,
        } => commands::mail::send(
            &cli,
            to,
            kind,
            subject,
            body.clone(),
            body_file.clone(),
            attachments.clone(),
            reply_to.clone(),
        ),
        Commands::Inbox => commands::mail::inbox(&cli),
        Commands::Read { id } => commands::mail::read(&cli, id),
        Commands::Reply { id, body, subject } => {
            commands::mail::reply(&cli, id, body.clone(), subject.clone())
        }
        Commands::Wait { timeout_secs } => commands::mail::wait(&cli, *timeout_secs),
        Commands::List { all } => commands::mail::list(&cli, *all),
        _ => {
            println!("not yet implemented");
            std::process::exit(1);
        }
    };
    if let Err(e) = result {
        if cli.json {
            output::fail_json(&e.to_string());
        } else {
            eprintln!("error: {e}");
        }
        std::process::exit(1);
    }
}
