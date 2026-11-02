//! `cmail-relayd` — the cmail reference relay server binary.
//!
//! Plaintext HTTP only: run behind a TLS reverse proxy in production (the
//! protocol REQUIRES TLS outside loopback testing, spec §2.2).

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "cmail-relayd",
    about = "cmail reference relay server (wire protocol v1)"
)]
struct Args {
    /// Relay root directory (mailboxes/ and nonces/ live here); created if absent.
    #[arg(long)]
    root: PathBuf,
    /// Address to bind, e.g. 127.0.0.1:8080.
    #[arg(long, default_value = "127.0.0.1:8080")]
    addr: String,
    /// Days a parcel is retained before lazy garbage collection.
    #[arg(long, default_value = "7")]
    retention_days: u64,
    /// Not yet implemented: run behind a TLS reverse proxy.
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// Not yet implemented: run behind a TLS reverse proxy.
    #[arg(long)]
    tls_key: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.tls_cert.is_some() || args.tls_key.is_some() {
        anyhow::bail!("--tls-cert/--tls-key coming in a follow-up; run behind a TLS reverse proxy");
    }
    cmail_relayd::run_server(args.root, &args.addr, args.retention_days)
}
