use crate::output;
use crate::Cli;
use anyhow::Result;
use cmail_core::authority::{system_authority, Assurance, AuthorityStatus};

fn assurance_label(assurance: Assurance) -> &'static str {
    match assurance {
        Assurance::None => "none",
        Assurance::Advisory => "advisory",
        Assurance::Moderate => "moderate",
        Assurance::Strong => "strong",
    }
}

fn print_status(status: &AuthorityStatus) {
    println!(
        "authority: {}",
        if status.available {
            "available"
        } else {
            "unavailable"
        }
    );
    println!("backend: {}", status.backend);
    println!("assurance: {}", assurance_label(status.assurance));
    match &status.fingerprint {
        Some(fingerprint) => println!("fingerprint: {fingerprint}"),
        None => println!("fingerprint: (none)"),
    }
    if let Some(grant) = &status.last_grant {
        println!("last grant: {grant}");
    }
}

pub fn init(cli: &Cli) -> Result<()> {
    let status = system_authority().init()?;
    if cli.json {
        output::print_json(&status);
    } else {
        println!("authority initialized");
        print_status(&status);
    }
    Ok(())
}

pub fn status(cli: &Cli) -> Result<()> {
    let status = system_authority().status()?;
    if cli.json {
        output::print_json(&status);
    } else {
        print_status(&status);
    }
    Ok(())
}
