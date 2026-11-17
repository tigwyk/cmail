# Human authority is anchored in the OS credential store

- Status: accepted
- Date: 2026-11-16

cmail's human-only powers (approval, keyring, allowlist, relay selection, quarantine release) must be enforced against a trust anchor that the agent's OS account cannot write. We decided to keep an Ed25519 **authority** key in the platform credential store behind a user-presence check, and to derive every policy decision from **authority records** — canonically encoded, signed, append-only decisions — instead of from unsigned keyring, config, or approval files.

## Context

In 0.3.1 the human/agent boundary is advisory. The human and every agent run as the same OS user, so Unix file permissions are not a boundary: any process that can read the mailbox root can approve its own held mail, add a key, edit the outbound allowlist, redirect the pickup relay, release quarantined mail, or rewrite the audit log. A prompt-injected agent can turn one injected instruction into durable policy, not just a single bad send.

The product already claims that trust is rooted in cryptographic evidence. Envelope signatures prove who sent a message, but nothing proves that a *policy change* was made by the human. Signing policy with a key that lives under the mailbox root would only move the forgery target: an attacker who can write the root can replace both a record and its verifying public key.

Terms used below: *Authority* is the human-held signing capability; an *Authority record* is one signed append-only decision; *Effective policy* is the state derived only from valid records.

## Decision

### Trust anchor: key in the OS credential store

The authority keypair is Ed25519. The private key is created in and never leaves the OS credential store except as a signing operation gated by user presence. The public key is read from the credential store at verification time, identified by a display fingerprint; it is never loaded from a writable file under the mailbox root.

Unsigned state cannot grant trust or permission because the attacker shares the human's OS account. A JSON or TOML file that an agent can write is evidence of nothing: it can be replaced atomically, and so can any public key stored beside it. Only a signature that verifies against the credential-store public key distinguishes a human decision from agent-written state. Reading the public half from the credential store closes the substitution attack — an attacker can add all the records it likes, but they verify against the wrong key and are ignored.

### Presence-gated signing

Human-only commands ask the authority backend for a signature. The backend requires a user-presence check on every grant; a process running as the human cannot satisfy it without the human's action. This is not agent detection: agents are not special-cased and there is no environment-variable bypass in release builds. An agent that invokes a human-only command receives a typed `authority required` refusal naming the action its human must take.

Presence is not attestation of intent. It proves a human approved *a prompt*, not that the human understood the action; the CLI still prints root-wide scope for approvals with `--remember`, allowlist changes, and relay changes.

### Canonical signed append-only authority records

Every human decision is one record containing:

- a format version;
- a monotonically increasing sequence number;
- a timestamp;
- an action and its subject (`key_add`, `key_remove`, `allow_add`, `allow_remove`, `relay_set`, `relay_clear`, `approve`, `reject`, `quarantine_release`, and policy-mode changes);
- a digest of the action payload;
- the signer fingerprint;
- the hash of the previous record (`prev`, genesis for sequence 1);
- a signature over the canonical record bytes.

Subjects are namespaced by family: `key:<name>:<public-key>` for keyring grants and revocations, `allow:<name>` for outbound allowlist entries, `approval:<message-id>` for approve/reject, `quarantine:<message-id>` for quarantine release, and the singletons `relay`, `mode:outbound`, and `mode:inbound`. A record whose subject is not in its action's namespace is refused at append and ignored by the fold, so an allow entry can never supersede an approval id. Each record also retains the signed decision payload, so a singleton setting resolves latest-wins instead of leaving an older value live. These namespaces, not the format version, are the compatibility marker for the change: version-1 records written before the scheme carry unnamespaced subjects, remain signature-verified and advance the chain, but never enter effective policy. Adoption must be re-run to write the namespaced forms.

Records are written to an append-only log and are never edited or deleted. Canonical encoding reuses `canonical_json`, the same deterministic serializer used for envelope signing, so signatures are stable across platforms. `approve` and `reject` bind one message id; a record cannot be replayed for another message. The latest valid record per subject wins, so revocation is another record rather than a deletion. The fold ignores records with an invalid signature, a sequence gap, a duplicate, or an unknown version, deterministically; the log loader is stricter and fails closed on a corrupt interior record instead of silently dropping it.

### Log storage is root-scoped; the chain head is pinned beside the key

One log per mailbox root (`authority.log`, one canonical JSON record per line) is shared by every backend, so policy survives a process restart on all platforms. Key material stays in the OS credential store; the log holds no secrets. Appends run under an exclusive file lock (`authority.log.lock`), so concurrent processes never interleave a line or reuse a sequence number. An incomplete final line from an interrupted append is ignored and truncated by the next append. Because a log under the mailbox root could be truncated or deleted by an agent, every append also pins `(sequence, chain-head hash)` in the credential store beside the key; a load fails closed when the log is behind that pin, has a different hash at the pinned sequence, or is missing entirely. A replaced log signed by another key fails signature verification.

### Effective policy is verified on read

Trust computation, the outbound gate, relay selection, approvals, and quarantine release consume only Effective policy. Verification happens when state is read at the service boundary — not when a file is written, and not only in the CLI — so MCP callers and hand-edited files get the same result. Legacy `keyring.json`, `config.toml`, and pending-approval files become adoption inputs and, at most, a derived cache. A cache write never grants trust or permission.

### Adoption and visibility

`authority init` creates the key. `authority adopt` shows the legacy keyring, outbound allowlist, relay URL, outbound and inbound policy modes, pending approvals, and quarantine releases a pre-enforcement build audited (only while a quarantined or archived copy survives, so the diff names sender and subject) as a diff, then writes one signed batch after an explicit human confirmation; declining leaves legacy state inert. Adoption is idempotent. `authority status` reports the authority fingerprint, backend, assurance level, and last grant, so an operator can tell whether enforcement is real on this machine. Audit events record the authority record id behind each applied decision; the audit log is append-only but is not itself a trust boundary. The operator runbook — upgrade sequence, backup, rollback, lost-key recovery, and mixed-version rules — is `docs/authority-operations.md`.

## Platform assurance

Assurance is reported honestly by `authority status`. "Strong" means the key is not silently usable by a same-user process and each use requires OS-verified presence. "Moderate" means presence is checked but the key material is not cryptographically bound to that check. "Advisory" means the credential store is unlocked with the login session and enforcement is a speed bump against a same-user attacker.

| Platform | Backend | Presence check | Assurance | Honest limitation |
| --- | --- | --- | --- | --- |
| macOS | Login Keychain generic password + LocalAuthentication | Touch ID / passcode prompt | Advisory (no hardened build shipped) | The command-line tool lacks the data-protection entitlement for a `kSecAttrAccessControl` item and is not built with the hardened runtime. Presence is an in-process speed bump: the item is not cryptographically bound to the check, and a same-user process can bypass it (for example with `DYLD_INSERT_LIBRARIES`). Ed25519 is also not a Secure Enclave algorithm, so the key is not hardware-bound; a human can be tricked into approving a prompt. Developer ID signing with the hardened runtime plus a presence-bound Keychain item is future work, not shipped. |
| Windows | Credential Manager (DPAPI) + Windows Hello | Windows Hello via `UserConsentVerifier` | Unverified at runtime; `authority status` reports Moderate if the backend answers | Hello proves the human is present, but the DPAPI-protected blob is not cryptographically bound to that check; a same-user process that locates the blob can decrypt it after login. This project has not verified the prompt, denial, or credential lifecycle on Windows at runtime, so documentation must not claim enforcement there. |
| Linux | Secret Service (GNOME Keyring / KWallet) | Collection unlock | Advisory | A login-keyring collection is typically unlocked for the session and readable by any same-user process; Secret Service has no per-use presence guarantee, and `authority_linux.rs` always reports Advisory with no polkit. Where no usable backend exists, human-only commands fail closed. |

No platform reports Strong, so public documentation claims "advisory" for macOS and Linux and "unverified at runtime" for Windows. No platform is documented as an enforced OS boundary, and documentation must match `authority status` on the host in question rather than promise a boundary the backend cannot provide.

## Mixed-version operation

The authority log is not a downgrade-compatible format.

- Old (0.3.x) binaries ignore authority records and continue to read legacy keyring, config, and pending files. They can appear to change policy that new binaries do not honor, and they cannot see signed policy at all.
- New binaries ignore unsigned legacy state except during adoption. Upgrading without adoption makes protected state empty: mail is untrusted, sends are held, and no relay is configured.
- All binaries sharing a mailbox root must be upgraded together. Mixed operation is documented as unsupported, not silently tolerated.
- Records with a version a binary does not understand are ignored; unknown fields are not interpreted. The Parcel format, relay wire protocol, transport, and routes are unchanged, so relays remain blind to policy.

## Backup, rollback, and lost key

**Backup.** Snapshot the mailbox root before `authority init` and before `authority adopt`. Back up the authority *public* key fingerprint and the authority log with that snapshot. The Ed25519 private key is not exportable in this iteration; copying the credential-store item is not a supported backup and must not be documented as one.

**Rollback.** Stop every cmail process on the root, restore the pre-adoption root snapshot, and run the previous binary. The restored snapshot contains the legacy files and no authority log, so the old binary resumes its prior behavior. Rollback discards every signed decision made since the snapshot; held mail stays held, and re-adoption is required after returning to a new binary. The previous binary ignores the pinned chain head; a new binary fails closed on the restored root because the log is behind the head pinned in the credential store. That is the intended truncation alarm: clear the pinned head item deliberately (macOS Keychain account `authority-log-head-v1`, Secret Service purpose `authority-head`, or Credential Manager target `cmail.authority.log-head.v1`) before running the new binary.

**Reset.** `cmail authority reset` is the recovered-key path: after a presence prompt it deletes the pinned head and the authority log, then provisions a fresh authority key. Every previous signed decision is discarded, and records signed by the old key never verify again. Snapshot the mailbox root first; reset cannot restore deleted records.

**Lost key.** If the credential-store item is lost or the backend cannot produce signatures, cmail fails closed: human-only commands return a typed error, trust is empty, sends are held, and relay selection is disabled. Recovery is a deliberate re-initialization under a new authority key followed by re-adoption of the intended state. There is no automatic revocation or rotation: records signed by the lost key no longer verify, so loading the old log fails closed. Recovery therefore uses `cmail authority reset`, a presence-gated human step, to remove the stale log and pinned head before the new key's first record; key rotation and recovery of a compromised human session are out of scope for this iteration and require their own design.

## Residual bypasses

These are accepted, not solved:

- **Same-user network egress.** An agent can speak the relay wire protocol directly, with its own identity key or a stolen one, without invoking cmail's outbound gate. Signing protects policy state, not network capability. Only OS-level egress control or a policy-enforcing relay would change this.
- **Direct filesystem injection into local mailboxes.** An agent can build a validly signed envelope and write it straight into another local identity's inbox, bypassing both the outbound gate and authority records. Fetched remote mail and injected local mail are currently indistinguishable by file layout. Receive-side provenance and freshness are a separate design.
- **Local confidentiality.** The root holder can read local plaintext; sealed mail protects transport and storage from relays and non-recipients, not from the OS user.
- **Availability.** A same-user process can delete or corrupt the authority log, mailbox, or audit log. Fail-closed behavior limits the damage but does not prevent denial of service.

## Rejected alternatives

- **File-based authority key under the mailbox root.** Rejected: the attacker can read or replace the private key and the verifying public key. It provides no boundary against the exact threat — a same-user agent editing state.
- **TTY prompt or interactive confirmation.** Rejected: an agent can allocate a pty and answer it, so it is automation with extra steps, not a presence check. It also fails on headless hosts and gives no OS-backed identity.
- **CLI-only checks.** Rejected: checks in the CLI do not bind state. Hand-edited files, MCP calls, or a modified command path bypass them. Verification must happen where Effective policy is read.
- **Environment-selected authority backend in release.** Rejected: a test convenience would become a production bypass. Release builds have no injectable backend; tests substitute the authority port in-process.
- **Hardware security keys, TPM attestation, per-identity authority.** Deferred, not rejected: they add availability and management cost beyond this iteration. Authority remains root-wide.

## Consequences

- Legacy files become inert inputs; the upgrade is a visible, signed adoption step rather than a silent migration.
- The service boundary gains one authority port (`load_effective_policy`, `sign_action`, `status`) resolved once per service instance and injected into trust, gate, relay, approvals, and quarantine.
- Agents keep send, read, reply, wait, list, and fetch unchanged. The MCP surface gains no new approval or trust tools.
- Some supported platforms cannot honestly claim a boundary. That is reported in `authority status` and in documentation rather than papered over.
