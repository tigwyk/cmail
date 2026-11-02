//! `cmail-relayd` — the cmail reference relay server (wire protocol v1,
//! spec `2026-11-01-cmail-relays-design.md` §2/§2.2).
//!
//! File-backed, zero-trust, single-relay (no forwarding, no accounts, no
//! admin API). The server depends on `cmail-core` ONLY for `Parcel`
//! validation, `fingerprint_of`, and challenge-signature verification — it
//! never inspects envelope interiors. Server code lives outside core so it
//! can never leak into agent-facing surfaces.
//!
//! Plaintext HTTP only: TLS termination is the deployer's responsibility
//! (reverse proxy); loopback is the insecure-local test mode.

pub mod server;
pub mod store;

pub use server::RelayServer;

/// Run the relay server: bind, print the bound address, serve until the
/// process is stopped (blocks). `cmail relay-serve` (CLI, R6) delegates here.
pub fn run_server(root: std::path::PathBuf, addr: &str, retention_days: u64) -> anyhow::Result<()> {
    let server = RelayServer::start(addr, root, retention_days)?;
    println!("cmail-relayd listening on {}", server.base_url());
    server.wait();
    Ok(())
}
