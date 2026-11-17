# Authority operations: backup, upgrade, rollback, lost keys

`docs/adr/0001-human-authority.md` is the design record. This page is the
operator runbook for it: how to upgrade a mailbox root, what a backup does and
does not restore, how to roll back, how to recover a lost authority key, and
which platform claims are honest.

## What is enforced, and what is not

Human-only decisions are **authority records**: canonically encoded, signed,
append-only entries in `<root>/authority.log`. The effective policy used by
approvals, the keyring, the outbound allowlist, relay selection, policy modes,
and quarantine release is folded only from records that verify against the
authority public key in the OS credential store.

- Editing `keyring.json`, `config.toml`, pending-mail files, or `authority.log`
  by hand grants nothing. Every protected read fails closed or ignores the edit
  (`crates/cmail-cli/tests/tamper.rs`, `cargo test -p cmail-core --lib`).
- The root-scoped record log holds no secrets. The private authority key lives
  only in the OS credential store behind a user-presence check and cannot be
  exported or backed up.
- Enforcement is at the **service boundary**, not by file permissions. The
  human and every agent share one OS account, so the strength of the boundary
  is whatever presence check the platform actually provides. No platform
  currently claims a strong OS boundary.

## Platform assurance

`cmail authority status` reports the backend, assurance, fingerprint, and last
grant. The documentation claim must match that report.

| Platform | Backend | Presence check | Reported assurance | Runtime verification | Honest limitation |
| --- | --- | --- | --- | --- | --- |
| macOS | Login Keychain generic password + LocalAuthentication | Touch ID / passcode prompt | `advisory` | Manual, not in CI | Presence is in-process. The Keychain item is not cryptographically bound to the check, and a same-user process can bypass it (for example with `DYLD_INSERT_LIBRARIES`). Ed25519 is not a Secure Enclave algorithm, so the key is not hardware-bound. A developer can be tricked into approving a prompt. |
| Linux | Secret Service (GNOME Keyring / KWallet) | Collection unlock | `advisory` | Not covered in CI | A login keyring is typically unlocked for the whole session and readable by any same-user process; Secret Service gives no per-use presence guarantee, and `authority_linux.rs` always reports Advisory with no polkit. Where no backend is usable, human-only commands fail closed. |
| Windows | Credential Manager (DPAPI) + Windows Hello | Windows Hello via `UserConsentVerifier` | Backend reports `moderate` when it answers; **unverified at runtime** | Not covered in CI | Windows Hello is called through the OS API, but this project has not verified the end-to-end prompt, denial, or credential lifecycle on Windows at runtime. The DPAPI-protected blob is not cryptographically bound to the Hello check. Do not claim enforcement on Windows until that verification exists. |

No platform reports `strong`, so no platform gets an "enforced OS boundary"
claim. What is enforced everywhere is the signed-policy rule: unsigned state
cannot grant trust, permission, relay selection, a mode change, or a release.

The macOS backend is **not** hardened: the release binaries are not Developer
ID signed with the hardened runtime, and the Keychain item is not a
data-protection `kSecAttrAccessControl` item. Adding Developer ID signing, the
hardened runtime, and a presence-bound Keychain item would turn this row into a
future assurance upgrade. It is future work, **not shipped**.

## Upgrade sequence

0. **Plan the outage.** Every binary sharing the root must run the new version.
   Mixed versions are unsupported (below).
1. **Stop the writers.** Stop every cmail process using the root: MCP servers,
   `cmail` runs, and any schedulers. Then snapshot the root (below).
2. **Install the new binary** everywhere the root is used. Do not start agents
   against the root until adoption finishes.
3. **Create the authority key:**

   ```bash
   cmail authority init
   ```

   This provisions the Ed25519 authority key in the OS credential store and
   requires a human presence check. The private key never leaves the store.

4. **Adopt legacy policy in one confirmed batch:**

   ```bash
   cmail authority adopt
   ```

   The command prints a diff and asks for confirmation. One signed batch
   migrates the legacy keyring, outbound allowlist, relay URL, outbound and
   inbound policy modes, pending approvals, and quarantine releases a
   pre-enforcement build had audited. Each proposed release shows the message
   id, sender, and subject, and is offered only while a quarantined or archived
   copy still exists; an audited id with no surviving copy stays locked.
   Declining writes nothing and leaves legacy files inert. Adoption is
   idempotent: re-running it proposes only what is not already covered by a
   valid record.

5. **Verify:**

   ```bash
   cmail authority status
   cmail mode show
   cmail relay show
   cmail allow list
   ```

   `authority status` must report the backend, fingerprint, and an assurance
   level you accept. `allow list`, relay selection, and both modes come from
   signed records, not from `config.toml` (the legacy `inbound` key only
   applies when no signed mode exists and the key is reachable).

6. **Enforce.** Restart agents and MCP servers. From here, hand-edited
   `keyring.json`, `config.toml`, pending files, and forged `authority.log`
   lines have no effect: protected actions fail closed or ignore the edit.

## Backup

Back up the **mailbox root** (default `~/.cmail`). Stop processes first so the
snapshot is consistent.

```bash
tar -czf cmail-root-$(date +%Y%m%d).tgz -C ~ .cmail
```

Keep a snapshot taken **before** `authority init` if you may need to return to
the pre-authority state. Backups cover identities, mailboxes, `keyring.json`,
`config.toml`, `audit.log`, and `authority.log` (signed decisions).

A backup **cannot** restore the authority key. The key exists only in the OS
credential store and is never exported. A restored snapshot with a live
credential-store key still verifies its own log; a snapshot on a machine or
account with no key is data-only until a new key is created and adoption is
run again.

The OS credential store also holds a pinned `(sequence, chain-head)` beside the
key. New binaries fail closed if `authority.log` is missing, shorter than the
pin, or has a different hash at the pinned sequence. Do not restore just the
log from an older snapshot while the pin is newer: either keep the current log
or recover with `authority reset` and re-adopt.

## Rollback

Rollback means restoring the previous binary and the mailbox snapshot. Signed
records are ignored by pre-authority binaries; they keep reading whatever
legacy `keyring.json` / `config.toml` the snapshot contains.

1. Stop every cmail process.
2. Restore the mailbox-root snapshot.
3. Reinstall the previous binary.
4. Start agents.

Consequences to state out loud:

- Decisions signed after the snapshot are not visible to the old binary. It
  sees the legacy files as of the snapshot (which, before adoption, were not
  rewritten).
- The authority key and its pinned head stay in the credential store. Rolling
  forward again runs `authority adopt`, which is idempotent; restoring an older
  `authority.log` under a newer pin fails closed (see Backup).
- If rollback must also discard signed policy, use the destructive recovery
  below (`authority reset`); it deletes every signed decision.

## Lost key and recovery

Symptoms: `authority status` reports `available: false` / `fingerprint:
(none)`, or human-only commands fail with `authority unavailable`. Reading mail
and normal send/read/reply/wait/list/fetch keep working; every protected
decision is refused.

- **The credential-store item is missing, erased, or unreadable.** The log may
  still exist, but no key can verify it. Recover with:

  ```bash
  cmail authority reset
  cmail authority adopt
  ```

  `reset` requires a human presence check. It deletes the pinned head and
  `authority.log`, provisions a fresh key, and cannot be undone: previously
  signed allowlist entries, keyring grants, relay and mode records, approvals,
  and quarantine releases are gone. Held mail stays held; released quarantine
  mail stays archived. `adopt` then re-signs whatever legacy state is present.
  Running plain `cmail authority adopt` against the old-key log without
  `reset` fails with `authority invalid`: the new key cannot verify it.
  If `reset` cannot prompt (no usable backend, locked session), there is no
  file or environment fallback: fix the credential-store session first.

- **The human denies the presence prompt.** Nothing changes. Recovery is
  retryable; a denial writes no record and deletes nothing.

- **The log was truncated or replaced but the key remains.** `authority status`
  still shows the key; signed-policy reads fail with `authority invalid`. Do
  not hand-edit the log. Restore the matching log from backup if its head
  matches the pin; otherwise run `authority reset` and re-adopt, accepting the
  loss of signed decisions.

- **Lost key plus lost backup.** Mail, identities, and audit history remain in
  the root. Authority history cannot be reconstructed: reset and re-adopt from
  the legacy files that remain. Pending approvals may need to be reviewed and
  approved again.

## Mixed-version operation (unsupported)

The authority log is not a downgrade-compatible format.

- Pre-authority (0.3.x) binaries ignore authority records and read legacy
  `keyring.json`, `config.toml`, and pending files. They can appear to change
  policy that new binaries do not honor.
- New binaries grant nothing from unsigned legacy state. Unsigned grants,
  relay selection, and outbound mode are ignored; legacy keyring routes are
  used only for routing and display, never trust; and the legacy `inbound`
  mode applies only when no signed mode exists and the key is reachable, so a
  legacy `known-only` can still tighten. Upgrading without adoption leaves
  protected state empty: mail is untrusted, sends are held, and no relay is
  configured.
- All binaries sharing a mailbox root must be upgraded together. There is no
  supported mixed-version mode.
- Records with a version a binary does not understand are ignored; unknown
  fields are not interpreted. The Parcel format, relay wire protocol,
  transport, and routes are unchanged, so relays remain blind to policy.

## What still is not protected

Signed policy does not close same-user network egress, direct filesystem
injection into another local inbox, local plaintext confidentiality, or
availability (an attacker can delete the log or mailboxes). Those accepted
limitations are listed in `docs/adr/0001-human-authority.md` under
"Consequences" and must not be described as solved.

## Verification

Release readiness for this behavior is exercised without a real presence
prompt:

```bash
cargo test -p cmail-core --lib
cargo test -p cmail-cli --test lifecycle
cargo test -p cmail-cli --test tamper
cargo test -p cmail-cli --test authority_regression
cargo test -p cmail-mcp
```

- `crates/cmail-cli/tests/tamper.rs` — hand-edited keyring, allowlist, config
  modes/relay, approvals, quarantine, and authority-log records: every
  protected action fails closed or ignores the edit.
- `crates/cmail-cli/tests/authority_regression.rs` — normal send, read, reply,
  wait, list, and fetch under a valid signed policy.
- `crates/cmail-core/src/{authority,adoption,policy,service}.rs` unit tests —
  fold, chain, adoption, and service-boundary fail-closed behavior.
