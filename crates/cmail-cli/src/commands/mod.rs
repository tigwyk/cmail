pub mod account;
pub mod admin;
pub mod authority;
pub mod mail;

/// Open the service with the authority port selected for this invocation
/// (system authority in release; the debug-only test seam in tests). Every
/// command that reads signed policy goes through here.
pub(crate) fn open(cli: &crate::Cli) -> anyhow::Result<cmail_core::Cmail> {
    Ok(cmail_core::Cmail::open_with_authority(
        &cli.root_path()?,
        authority::authority(cli),
    )?)
}
