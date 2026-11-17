use crate::output;
use crate::Cli;
use anyhow::Result;
use cmail_core::adoption::AdoptionPlan;
#[cfg(debug_assertions)]
use cmail_core::authority::UnavailableAuthority;
use cmail_core::authority::{system_authority, Assurance, Authority, AuthorityStatus};
use cmail_core::Cmail;
use std::io::{self, Write};

/// Resolve the authority port for this invocation. Debug builds can force the
/// fail-closed backend so the CLI failure path is testable without touching a
/// real credential store; release builds compile the override out.
fn authority(cli: &Cli) -> &'static dyn Authority {
    #[cfg(debug_assertions)]
    if cli.test_unavailable_authority {
        static UNAVAILABLE: UnavailableAuthority = UnavailableAuthority;
        return &UNAVAILABLE;
    }
    #[cfg(not(debug_assertions))]
    let _ = cli;
    system_authority()
}

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
    if let Some(explanation) = &status.explanation {
        println!("explanation: {explanation}");
    }
}

pub fn init(cli: &Cli) -> Result<()> {
    let status = authority(cli).init()?;
    if cli.json {
        output::print_json(&status);
    } else {
        println!("authority initialized");
        print_status(&status);
    }
    Ok(())
}

fn print_plan(plan: &AdoptionPlan) {
    if plan.first_adoption() {
        println!(
            "Back up the mailbox root now: the authority private key cannot be exported.\n\
             Rollback restores that snapshot and the previous binary."
        );
    }
    if plan.pending.is_empty() {
        println!("nothing to adopt");
    } else {
        println!("legacy policy to sign (root-wide):");
        for entry in &plan.pending {
            println!("  + {}", entry.summary);
        }
    }
    if !plan.already_adopted.is_empty() {
        println!("already adopted:");
        for entry in &plan.already_adopted {
            println!("  = {}", entry.summary);
        }
    }
}

fn confirm() -> Result<bool> {
    eprint!("sign these records? [y/N] ");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

pub fn adopt(cli: &Cli) -> Result<()> {
    let c = Cmail::open(&cli.root_path()?)?;
    let authority = authority(cli);
    let plan = c.adoption_plan(authority)?;
    if !cli.json {
        print_plan(&plan);
    }
    let confirmed = plan.pending.is_empty() || confirm()?;
    let outcome = c.sign_adoption(authority, plan, confirmed)?;
    if cli.json {
        output::print_json(&outcome);
    } else if outcome.plan.pending.is_empty() {
        println!("nothing to adopt");
    } else if confirmed {
        println!("adopted {} signed record(s)", outcome.signed.len());
    } else {
        println!("declined; no records written");
    }
    Ok(())
}

pub fn status(cli: &Cli) -> Result<()> {
    let status = authority(cli).status()?;
    if cli.json {
        output::print_json(&status);
    } else {
        print_status(&status);
    }
    Ok(())
}
