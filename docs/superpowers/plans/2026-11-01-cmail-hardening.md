# cmail Hardening Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the deferred findings from the v1 whole-branch review (input validation, error fidelity, durability, service consistency, MCP polish, test gaps) before the repo is publicized.

**Architecture:** Surgical modifications to the existing three-crate workspace (`cmail-core`, `cmail-cli`, `cmail-mcp`) — no new crates, no public-API redesigns. One new tiny module (`fsutil`) for durable writes. Behavior-affecting changes are limited to: error taxonomy (better messages, never worse), `allow add/remove` gaining JSON status output, `--body`+`--body-file` together now an error, MCP missing-method now `-32600`, MCP wait capped at 600s.

**Tech Stack:** unchanged (Rust 2021; `time` gains the `parsing` feature).

## Global Constraints

- All v1 constraints still bind: envelope limits, trust strings (`verified|untrusted|spoof_suspect|invalid`), verbatim UNTRUSTED delimiters, human-only powers CLI-only, exit codes (0 ok / 1 error), `--json` errors on stdout.
- **Do not break locked JSON shapes**: CLI/MCP output for send (`{"status":..}`), inbox/list (InboxItem array), read (ReadMessage), approvals (HeldMessage array) — unless a task explicitly says to extend (only `allow add/remove` gains output; nothing changes shape).
- New `time` feature only: `time = { version = "0.3", features = ["formatting", "parsing"] }` (workspace dep). No other dependency changes.
- Fail-closed rules stay fail-closed: `was_released` must keep rejecting an unparseable/absent audit log; strict-mode routing unchanged.
- Every task: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings` clean, full `cargo test --workspace` green before commit.
- House style: `#[expect(...)]` over `#[allow(...)]` when appeasing lints; comments cite the review finding they close.
- Baseline at plan time: main @ fa364db, 50/50 tests.

---

### Task H1: Identity-name path validation (defense-in-depth)

Closes: final-review "one new observation" (identity_dir joins unvalidated names) + ledger T3 minor.

**Files:**
- Modify: `crates/cmail-core/src/identity.rs`
- Test: same file (test module)

**Interfaces:**
- Consumes: existing `validate_name`, `identity_dir` (private), `identity_exists`, `load_identity`, `create_identity`.
- Produces: unchanged public signatures. New behavior: `identity_exists` returns false for names failing `validate_name`; `load_identity` validates before reading (planted traversal key files can never load).

- [ ] **Step 1: Write the failing tests** (append to identity.rs test module)

```rust
    #[test]
    fn identity_names_are_path_safe() {
        let root = TempDir::new().unwrap();
        create_identity(root.path(), "real").unwrap();
        // Plant a key file at a traversal-relative location: root/identities/../evil/identities/real/key.ed25519
        let planted = root.path().join("evil").join("identities").join("real");
        fs::create_dir_all(&planted).unwrap();
        fs::write(planted.join("key.ed25519"), [0u8; 32]).unwrap();
        // Without validation, identity_exists(root, "../evil/identities/real") would find it.
        assert!(!identity_exists(root.path(), "../evil/identities/real"));
        assert!(identity_exists(root.path(), "real"));
        let err = load_identity(root.path(), "../evil/identities/real").unwrap_err();
        assert!(matches!(err, crate::error::CoreError::InvalidName(_)));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p cmail-core identity_names`
Expected: FAIL — `identity_exists` currently returns true for the planted traversal path.

- [ ] **Step 3: Implement**

In `identity_exists`:

```rust
pub fn identity_exists(root: &Path, name: &str) -> bool {
    // Path safety (final-review hardening): never join an unvalidated name.
    validate_name(name).is_ok() && identity_dir(root, name).join("key.ed25519").exists()
}
```

In `load_identity`, add as the first line:

```rust
    validate_name(name)?;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p cmail-core`
Expected: 41 tests PASS (39 + 1 new + truncated-key test already counted at baseline — report actual count; baseline is 50 workspace-wide after H-task additions from prior fixes; just require all green).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "fix(core): identity names path-validated before any join (hardening)"
```

---

### Task H2: Envelope parse validation (created RFC 3339, in_reply_to hex, CR in subject)

Closes: ledger T4 minors (created never validated at parse; in_reply_to hex-ness; CR not rejected).

**Files:**
- Modify: `crates/cmail-core/src/envelope.rs`, root `Cargo.toml` (time features), `Cargo.lock` (regenerated)
- Test: `crates/cmail-core/src/envelope.rs` (test module)

**Interfaces:**
- Produces: unchanged public API. `Envelope::parse` now rejects: `created` not parseable as RFC 3339, `in_reply_to` not 32 hex chars, subject containing `\r`.

- [ ] **Step 1: Add the `parsing` feature**

Root `Cargo.toml` workspace deps:

```toml
time = { version = "0.3", features = ["formatting", "parsing"] }
```

Run `cargo build --workspace` once to refresh `Cargo.lock`.

- [ ] **Step 2: Write the failing tests** (append to envelope.rs test module)

```rust
    #[test]
    fn parse_rejects_bad_created_in_reply_to_and_cr() {
        let (alice, _) = fixtures();
        let from_key = B64.encode(alice.verifying_key().as_bytes());
        let mut p = parts("alice", &from_key, "zoe");
        p.created = "not a date".into();
        assert!(build_and_sign("66".repeat(16).as_str(), &p, &alice).is_err());

        // parse-time rejection of a hand-edited envelope
        let mut env = build_and_sign("77".repeat(16).as_str(), &parts("alice", &from_key, "zoe"), &alice).unwrap();
        let tamper = |env: &Envelope, field: &str, value: String| {
            let mut e = env.clone();
            match field {
                "created" => e.created = value,
                "in_reply_to" => e.in_reply_to = Some(value),
                "subject" => e.subject = value,
                _ => unreachable!(),
            }
            // re-sign so ONLY the semantic rule is under test, not the signature
            build_and_sign(
                &e.id,
                &NewEnvelope {
                    from: e.from.clone(),
                    from_key: e.from_key.clone(),
                    to: e.to.clone(),
                    kind: e.kind.clone(),
                    subject: e.subject.clone(),
                    body: e.body.clone(),
                    attachments: e.attachments.clone(),
                    in_reply_to: e.in_reply_to.clone(),
                    created: e.created.clone(),
                },
                &alice,
            )
        };
        assert!(tamper(&env, "created", "yesterday".into()).is_err());
        assert!(tamper(&env, "in_reply_to", "zz".repeat(16)).is_err()); // right length, not hex
        assert!(tamper(&env, "in_reply_to", "ab".repeat(16)).is_ok());  // valid hex is fine
        assert!(tamper(&env, "subject", "has\rreturn".into()).is_err());
    }
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p cmail-core parse_rejects_bad`
Expected: FAIL — current `validate` accepts all three.

- [ ] **Step 4: Implement** (in `validate()`)

Replace the existing `in_reply_to` length check and the subject newline check with:

```rust
    if p.subject.contains('\n') || p.subject.contains('\r') {
        return bad("subject must be a single line");
    }
```

```rust
    if let Some(parent) = &p.in_reply_to {
        if parent.len() != 32 || !parent.chars().all(|c| c.is_ascii_hexdigit()) {
            return bad("in_reply_to must be a message id");
        }
    }
    if time::OffsetDateTime::parse(
        &p.created,
        &time::format_description::well_known::Rfc3339,
    )
    .is_err()
    {
        return bad("created must be an RFC 3339 timestamp");
    }
```

- [ ] **Step 5: Run tests, commit**

Run: `cargo test --workspace` — all green (now_rfc3339 output parses as Rfc3339; verify no existing fixture uses a non-parsing timestamp — all use `2026-11-01T12:00:00Z`, which parses).

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "fix(core): parse-time validation of created/in_reply_to/subject (hardening)"
```

---

### Task H3: Store error fidelity, files-only listing, attachment-copy rollback

Closes: ledger T8 minors (io-error collapse; list_ids matches dirs; copy TOCTOU/rollback — rollback only; TOCTOU itself stays accepted as trusted-fs).

**Files:**
- Modify: `crates/cmail-core/src/store.rs`
- Test: same file (test module)

**Interfaces:**
- Produces: unchanged signatures. Behavior: `read_raw`/`move_message`/`delete_message` map only `ErrorKind::NotFound` to `MessageNotFound`; other io errors propagate as `CoreError::Io`. `list_ids` lists regular files only. `copy_attachments` removes `attachments/<id>/` on any failure.

- [ ] **Step 1: Write the failing tests** (append to store.rs test module)

```rust
    #[test]
    fn io_errors_are_not_disguised_as_not_found() {
        let root = TempDir::new().unwrap();
        let store = MailStore::new(root.path());
        // a FILE where a directory is expected -> io error, not "not found"
        let blocker = root.path().join("blocker");
        fs::write(&blocker, b"x").unwrap();
        let err = store.read_raw(&blocker.join("sub"), "ab".repeat(16).as_str()).unwrap_err();
        assert!(matches!(err, crate::error::CoreError::Io(_)), "{err}");
        // genuinely absent -> MessageNotFound
        let err = store.read_raw(&store.inbox_dir("zoe"), "cd".repeat(16).as_str()).unwrap_err();
        assert!(matches!(err, crate::error::CoreError::MessageNotFound(_)));
    }

    #[test]
    fn list_ids_ignores_directories_named_mail() {
        let root = TempDir::new().unwrap();
        let store = MailStore::new(root.path());
        fs::create_dir_all(store.inbox_dir("zoe").join("trap.mail")).unwrap();
        assert!(store.list_ids(&store.inbox_dir("zoe")).is_empty());
    }

    #[test]
    fn copy_attachments_rolls_back_on_limit_trip() {
        let root = TempDir::new().unwrap();
        let store = MailStore::new(root.path());
        let big = root.path().join("big.bin");
        let mut bytes = vec![0u8; 1024];
        bytes[0..8].copy_from_slice(b"payload!"); // compresses poorly; keeps size honest
        fs::write(&big, bytes.repeat(1024)).unwrap(); // 1 MiB
        // 9 files -> count limit trips AFTER the dir is created and files written
        let many: Vec<PathBuf> = (0..9).map(|_| big.clone()).collect();
        assert!(store.copy_attachments("rollback1", &many).is_err());
        assert!(!store.attachments_dir("rollback1").exists(), "failed copy must not leave a dir behind");
    }
```

- [ ] **Step 2: Run to verify failures** — `cargo test -p cmail-core io_errors_are_not` (expects Io, gets MessageNotFound), `list_ids_ignores` (lists "trap"), `copy_attachments_rolls_back` (dir left behind).

- [ ] **Step 3: Implement**

`read_raw`:

```rust
    pub fn read_raw(&self, dir: &Path, id: &str) -> Result<String> {
        let path = Self::mail_path(dir, id)?;
        fs::read_to_string(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => CoreError::MessageNotFound(id.to_string()),
            _ => CoreError::Io(e),
        })
    }
```

Apply the same `map_err` closure to the `fs::rename` in `move_message` and `fs::remove_file` in `delete_message` (rename's first arg failing with NotFound is the "absent" case; keep mapping NotFound → MessageNotFound, everything else → Io).

`list_ids`: inside the entry loop, add before the extension check:

```rust
                if !e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    continue;
                }
```

`copy_attachments`: wrap the existing body after `fs::create_dir_all(&dir)?;` so failures clean up:

```rust
        match self.copy_attachments_inner(&dir, paths) {
            Ok(out) => Ok(out),
            Err(e) => {
                let _ = fs::remove_dir_all(&dir);
                Err(e)
            }
        }
    }

    fn copy_attachments_inner(&self, dir: &Path, paths: &[PathBuf]) -> Result<Vec<Attachment>> {
        // (existing loop body, unchanged, using `dir` instead of re-deriving it)
```

Move the count-limit check to the TOP of `copy_attachments` (before `create_dir_all`) so count overflows never create the dir at all.

- [ ] **Step 4: Run tests, commit**

Run: `cargo test --workspace` — all green.

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "fix(core): honest io errors, files-only id listing, attachment-copy rollback (hardening)"
```

---

### Task H4: Audit durability and display tolerance

Closes: ledger T5 minors (1/12 name pin, tail all-or-nothing) + T5/T8 fsync deferral for trust-bearing files.

**Files:**
- Create: `crates/cmail-core/src/fsutil.rs`
- Modify: `crates/cmail-core/src/lib.rs` (+1 module line), `crates/cmail-core/src/audit.rs`, `crates/cmail-core/src/keyring.rs`, `crates/cmail-core/src/config.rs`, `crates/cmail-core/src/store.rs`, `crates/cmail-cli/src/commands/admin.rs` (audit display call)
- Test: `crates/cmail-core/src/audit.rs` (test module)

**Interfaces:**
- Produces: `fsutil::write_durable(path: &Path, bytes: &[u8]) -> Result<()>` (write temp in same dir, `sync_data`, rename over target); `fsutil::append_line(root_file: &Path, line: &str) -> Result<()>` (append-mode single `write_all` + `sync_data`). `audit::tail_lossy(root, n) -> Result<Vec<AuditRecord>>` (skips malformed lines, for display only). `audit::tail` stays strict (used by the fail-closed `was_released` gate).

- [ ] **Step 1: Write the failing tests** (append to audit.rs test module)

```rust
    #[test]
    fn all_twelve_event_names_pinned() {
        for (evt, name) in [
            (AuditEvent::Init, "init"),
            (AuditEvent::Send, "send"),
            (AuditEvent::Held, "held"),
            (AuditEvent::Approve, "approve"),
            (AuditEvent::Reject, "reject"),
            (AuditEvent::Read, "read"),
            (AuditEvent::AllowAdd, "allow_add"),
            (AuditEvent::AllowRemove, "allow_remove"),
            (AuditEvent::KeyAdd, "key_add"),
            (AuditEvent::SpoofSuspected, "spoof_suspected"),
            (AuditEvent::Corrupt, "corrupt"),
            (AuditEvent::QuarantineRelease, "quarantine_release"),
        ] {
            let r = AuditRecord::now(evt, "t");
            let s = serde_json::to_string(&r).unwrap();
            assert!(s.contains(&format!("\"event\":\"{name}\"")), "{s}");
        }
    }

    #[test]
    fn tail_lossy_skips_garbage_but_tail_stays_strict() {
        let root = TempDir::new().unwrap();
        append(root.path(), &AuditRecord::now(AuditEvent::Send, "a")).unwrap();
        std::fs::write(root.path().join("audit.log"), format!("{{garbage\n{}\n", serde_json::to_string(&AuditRecord::now(AuditEvent::Read, "a")).unwrap())).unwrap();
        // overwrite happened above; re-append cleanly for a 2-good-1-bad file:
        std::fs::remove_file(root.path().join("audit.log")).unwrap();
        append(root.path(), &AuditRecord::now(AuditEvent::Send, "a")).unwrap();
        let mut f = std::fs::OpenOptions::new().append(true).open(root.path().join("audit.log")).unwrap();
        use std::io::Write;
        writeln!(f, "{{garbage").unwrap();
        append(root.path(), &AuditRecord::now(AuditEvent::Read, "a")).unwrap();
        assert!(tail(root.path(), 10).is_err(), "strict tail must reject the whole file");
        let lossy = tail_lossy(root.path(), 10).unwrap();
        assert_eq!(lossy.len(), 2);
        assert_eq!(lossy[1].event, AuditEvent::Read);
    }
```

(If the doubled write in the first part of the second test is awkward, keep only the clean 2-good-1-bad construction — the assertions are the contract.)

- [ ] **Step 2: Run to verify failure** — `tail_lossy` does not exist (compile error is the RED).

- [ ] **Step 3: Implement**

`fsutil.rs`:

```rust
use crate::error::Result;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Durable replace: write temp in the same dir, fsync, rename over target.
/// For trust-bearing files (keyring.json, config.toml, mail envelopes) whose
/// loss or tear would confuse the fail-closed gates.
pub fn write_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_data()?;
    drop(f);
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Durable append of one line to an append-only file (single write_all + fsync).
pub fn append_line(path: &Path, line: &str) -> Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(line.as_bytes())?;
    f.sync_data()?;
    Ok(())
}
```

`lib.rs`: `pub mod fsutil;` (alphabetical).

`audit.rs`: `append` body becomes `fsutil::append_line(&root.join("audit.log"), &format!("{}\n", serde_json::to_string(record)?))`; add:

```rust
/// Display-oriented tail: skips malformed lines instead of failing. The
/// fail-closed `was_released` gate keeps using strict `tail`.
pub fn tail_lossy(root: &Path, n: usize) -> Result<Vec<AuditRecord>> {
    let path = root.join("audit.log");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(&path)?;
    let mut records: Vec<AuditRecord> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    if records.len() > n {
        records.drain(..records.len() - n);
    }
    Ok(records)
}
```

`keyring.rs` `save`: replace tmp+rename with `crate::fsutil::write_durable(&path, serde_json::to_string_pretty(self)?.as_bytes())`. Same for `config.rs` `save` and `store.rs` `write_envelope` (envelope bytes = `serde_json::to_string_pretty(env)?`; keep the same tmp-suffix collision avoidance — `write_durable` uses `.tmp` extension which is what they used).

`admin.rs` audit display: call `tail_lossy` instead of `tail` (JSON output also becomes lossy — display path only).

- [ ] **Step 4: Run tests, commit**

Run: `cargo test --workspace` — all green (the audit display change is behavior-compatible for well-formed logs).

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "fix(core): durable writes for trust-bearing files; lossy audit display tail; 12-name pin (hardening)"
```

---

### Task H5: Service consistency and failure cleanup

Closes: ledger T8/T9/T10 service minors (orphaned attachments, approve recipient re-verify, reject audit honesty, invisible unparseable pending, cached default_identity, wait first-sleep latency).

**Files:**
- Modify: `crates/cmail-core/src/service.rs`
- Test: same file (test module)

**Interfaces:**
- Produces: unchanged signatures except `reject` (same signature, honest audit outcome). New behavior: send cleans up `attachments/<id>/` on any post-copy failure; approve errors `UnknownRecipient` if recipient identity vanished; approvals includes a placeholder row for unparseable pending mail; `resolve_identity`'s default_identity fallback reads fresh config; `wait` checks before first sleep.

- [ ] **Step 1: Write the failing tests** (append to service.rs test module)

```rust
    #[test]
    fn send_failure_cleans_up_attachments() {
        let (_root, c) = svc();
        let att = _root.path().join("note.txt");
        std::fs::write(&att, "x").unwrap();
        let before = std::fs::read_dir(_root.path().join("attachments")).map(|d| d.count()).unwrap_or(0);
        // invalid kind trips build_and_sign AFTER copy_attachments ran
        assert!(c.send(Some("alice"), "zoe", "shout", "s", "b", &[att], None).is_err());
        let after = std::fs::read_dir(_root.path().join("attachments")).map(|d| d.count()).unwrap_or(0);
        assert_eq!(before, after, "failed send must not orphan attachments");
    }

    #[test]
    fn approve_rejects_missing_recipient_identity() {
        let (_root, c) = svc();
        let SendOutcome::Held { id, .. } = c.send(Some("alice"), "zoe", "note", "s", "b", &[], None).unwrap() else { panic!() };
        std::fs::remove_dir_all(_root.path().join("identities").join("zoe")).unwrap();
        let err = c.approve(&id, false).unwrap_err();
        assert!(matches!(err, CoreError::UnknownRecipient(_)), "{err}");
    }

    #[test]
    fn approvals_list_unparseable_pending() {
        let (_root, c) = svc();
        c.store.ensure_mailbox("alice").unwrap();
        std::fs::write(
            c.store.pending_dir("alice").join(format!("{}.mail", "ab".repeat(16))),
            "garbage",
        )
        .unwrap();
        let apps = c.approvals(None).unwrap();
        assert!(apps.iter().any(|h| h.id == "ab".repeat(16) && h.subject.contains("unparseable")));
    }

    #[test]
    fn default_identity_read_fresh_from_disk() {
        let (root, c) = svc();
        assert!(c.resolve_identity(None).is_err());
        let mut cfg = c.config.clone();
        cfg.default_identity = Some("zoe".into());
        cfg.save(root.path()).unwrap();
        // same handle, no reopen:
        assert_eq!(c.resolve_identity(None).unwrap(), "zoe");
    }

    #[test]
    fn wait_with_zero_timeout_returns_immediately() {
        let (_root, c) = svc();
        let start = std::time::Instant::now();
        let _ = c.wait(Some("zoe"), std::time::Duration::from_secs(0)).unwrap();
        assert!(start.elapsed() < std::time::Duration::from_millis(200), "zero timeout must not sleep");
    }

    #[test]
    fn strict_mode_quarantines_unknown_senders() {
        let (root, c) = svc();
        // deliver one untrusted message (alice -> zoe, allowlisted for the test)
        c.allow_add("zoe").unwrap();
        let id = match c.send(Some("alice"), "zoe", "note", "s", "b", &[], None).unwrap() {
            SendOutcome::Sent { id } => id,
            _ => panic!(),
        };
        // flip to strict mode on disk; inbox() must quarantine the untrusted mail
        let mut cfg = c.config.clone();
        cfg.inbound = crate::config::InboundMode::KnownOnly;
        cfg.save(root.path()).unwrap();
        assert!(c.inbox(Some("zoe")).unwrap().is_empty());
        assert_eq!(c.store.list_ids(&c.store.quarantine_dir("zoe")), vec![id.clone()]);
        // back to permissive on a fresh handle: released-by-config, but still untrusted
        let mut cfg = c.config.clone();
        cfg.inbound = crate::config::InboundMode::Permissive;
        cfg.save(root.path()).unwrap();
        let c2 = Cmail::open(root.path()).unwrap();
        assert_eq!(c2.inbox(Some("zoe")).unwrap().len(), 0); // still in quarantine, not re-listed
        let _ = c2.quarantine_release(&id).unwrap();
        let msg = c2.read_message(Some("zoe"), &id).unwrap();
        assert_eq!(msg.trust, "untrusted");
        assert!(msg.body.contains("UNTRUSTED MAIL BODY"));
    }
```

- [ ] **Step 2: Run to verify failures** — all five fail against current code (attachments orphaned; approve succeeds; approvals empty; resolve errs on stale handle; wait sleeps 250ms).

- [ ] **Step 3: Implement** (all in `impl Cmail`)

send — wrap everything after `copy_attachments` and clean up on error:

```rust
        let id = new_id();
        let identity = load_identity(&self.root, &from)?;
        let attachment_meta = self.store.copy_attachments(&id, attachments)?;
        let outcome = self.send_gated(&id, &identity, &from, to, kind, subject, body, attachment_meta, reply_to);
        if outcome.is_err() {
            // no orphaned attachments/<id>/ on any failure (review hardening)
            let _ = std::fs::remove_dir_all(self.store.attachments_dir(&id));
        }
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    fn send_gated(
        &self,
        id: &str,
        identity: &crate::identity::Identity,
        from: &str,
        to: &str,
        kind: &str,
        subject: &str,
        body: &str,
        attachment_meta: Vec<crate::envelope::Attachment>,
        reply_to: Option<&str>,
    ) -> Result<SendOutcome> {
        let env = build_and_sign(
            id,
            &NewEnvelope {
                from: from.to_string(),
                from_key: identity.public_key_b64(),
                to: to.to_string(),
                kind: kind.to_string(),
                subject: subject.to_string(),
                body: body.to_string(),
                attachments: attachment_meta,
                in_reply_to: reply_to.map(str::to_string),
                created: now_rfc3339(),
            },
            &identity.signing,
        )?;
        // ... existing gate logic unchanged, using `from`/`to`/&env, returning the outcome
```

(Move the existing ensure_mailbox / gate / write / audit block into `send_gated` verbatim, adjusting `&from`→`from`, `&id`→`id`, `to` already `&str`.)

approve — re-verify recipient before the move:

```rust
        let (owner, env) = self.store.find_pending(id)?;
        if !identity_exists(&self.root, &env.to) {
            return Err(CoreError::UnknownRecipient(env.to));
        }
```

reject — honest outcome:

```rust
        let removed = std::fs::remove_dir_all(self.store.attachments_dir(id));
        let outcome = if removed.is_ok() { "deleted" } else { "deleted (attachments removal failed)" };
        // use `outcome` in the AuditRecord below instead of the literal "deleted"
```

approvals — replace the `if let Ok(env)` skip with an else-branch placeholder:

```rust
                let raw = self.store.read_raw(&self.store.pending_dir(&o), &id)?;
                match Envelope::parse(&raw) {
                    Ok(env) => out.push(HeldMessage {
                        id: env.id,
                        from: env.from,
                        to: env.to,
                        subject: env.subject,
                        created: env.created,
                    }),
                    Err(_) => out.push(HeldMessage {
                        id,
                        from: o.clone(),
                        to: String::new(),
                        subject: "<unparseable pending message>".into(),
                        created: String::new(),
                    }),
                }
```

resolve_identity — replace the `self.config.default_identity` block's config source:

```rust
        let cfg = Config::load_or_init(&self.root)?; // fresh: long-lived MCP process (H5)
        if let Some(n) = &cfg.default_identity {
            // ... existing existence check + return, using `cfg`
        }
```

wait — check before sleeping:

```rust
        let start = std::time::Instant::now();
        loop {
            let current = self.inbox(as_name)?;
            if current.iter().any(|i| !before.contains(&i.id)) || start.elapsed() >= timeout {
                return Ok(current);
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
```

- [ ] **Step 4: Run tests, commit**

Run: `cargo test -p cmail-core service -- --test-threads=1` then `cargo test --workspace` — all green.

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "fix(core): send attachment cleanup, approve recipient re-verify, honest reject audit, visible unparseable pending, fresh default_identity, instant wait timeout (hardening)"
```

---

### Task H6: MCP protocol polish and tool coverage

Closes: ledger T12 minors (dead error codes, -32600, uncapped wait, to_value unwrap) + T17 test-coverage duties (untested tools, untrusted wrapping via MCP).

**Files:**
- Modify: `crates/cmail-mcp/src/protocol.rs`, `crates/cmail-mcp/src/tools.rs`
- Test: `crates/cmail-mcp/tests/server.rs`

**Interfaces:**
- Produces: `tools::call(svc, as_name, params) -> Result<Value, String>` (String errors — codes were dead), `tools::clamp_wait_secs(u64) -> u64` (min 600) as a pub fn for unit testing. protocol: missing `method` → `-32600`. Tool descriptions updated (wait cap). No output-shape changes for success/error results.

- [ ] **Step 1: Write the failing tests** (append to server.rs)

```rust
#[test]
fn missing_method_is_minus_32600() {
    let root = setup();
    let out = drive(root.path(), &[r#"{"jsonrpc":"2.0","id":9,"params":{}}"#]);
    assert_eq!(out[0]["error"]["code"], -32600);
}

#[test]
fn wait_seconds_clamped_to_600() {
    assert_eq!(cmail_mcp::tools::clamp_wait_secs(0), 0);
    assert_eq!(cmail_mcp::tools::clamp_wait_secs(30), 30);
    assert_eq!(cmail_mcp::tools::clamp_wait_secs(600), 600);
    assert_eq!(cmail_mcp::tools::clamp_wait_secs(u64::MAX), 600);
}

#[test]
fn inbox_read_reply_wait_covered_via_mcp() {
    let root = setup();
    // deliver real untrusted mail to zoe using core (bypassing the gate directly)
    {
        let svc = cmail_core::Cmail::open(root.path()).unwrap();
        svc.allow_add("zoe").unwrap();
        let sent = svc.send(Some("alice"), "zoe", "note", "s", "hello via core", &[], None).unwrap();
        let cmail_core::service::SendOutcome::Sent { id } = sent else { panic!() };
        std::env::set_var("MCP_TEST_MSG_ID", &id);
    }
    let id = std::env::var("MCP_TEST_MSG_ID").unwrap();
    let lines: Vec<String> = vec![
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#.into(),
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.into(),
        format!(r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"cmail_inbox","arguments":{{}}}}}}"#),
        format!(r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"cmail_read","arguments":{{"id":"{id}"}}}}}}"#),
        format!(r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"cmail_reply","arguments":{{"id":"{id}","body":"roger"}}}}}}"#),
        format!(r#"{{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{{"name":"cmail_wait","arguments":{{"timeout_seconds":1}}}}}}"#),
    ];
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let out = drive(root.path(), &refs);
    std::env::remove_var("MCP_TEST_MSG_ID");
    let inbox: serde_json::Value = serde_json::from_str(out[1]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(inbox[0]["trust"], "untrusted");
    let read: serde_json::Value = serde_json::from_str(out[2]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert!(read["body"].as_str().unwrap().contains("UNTRUSTED MAIL BODY"));
    assert_eq!(read["fingerprint"].as_str().unwrap().len(), 16);
    let reply: serde_json::Value = serde_json::from_str(out[3]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(reply["status"], "held"); // zoe->alice not allowlisted
    let wait: serde_json::Value = serde_json::from_str(out[4]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert!(wait.as_array().unwrap().is_empty()); // read moved it to archive; wait sees nothing new
}
```

- [ ] **Step 2: Run to verify failures** — `-32600` test fails (currently -32601); `clamp_wait_secs` doesn't exist (compile); coverage test fails at `reply["status"]` Null (out[3] is wait — indexing assumes responses [init, inbox, read, reply, wait]; check alignment and fix indices if the notification ordering differs — the assertion intent is what matters).

- [ ] **Step 3: Implement**

protocol.rs — after the notification early-return, require `method`:

```rust
    let method = match msg.get("method") {
        Some(Value::String(s)) => s.clone(),
        _ => {
            return Some(json!({
                "jsonrpc": "2.0", "id": id,
                "error": {"code": -32600, "message": "invalid request: missing or non-string method"}
            }))
        }
    };
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
```

(Delete the old `method` extraction via `unwrap_or_default()`.)

tools.rs:

```rust
/// MCP-exposed wait is capped so a hostile/buggy caller can't pin the
/// sequential server indefinitely (review hardening).
pub fn clamp_wait_secs(secs: u64) -> u64 {
    secs.min(600)
}
```

Change `call`'s error type to `String` throughout: `fn internal<E: Display>(e: E) -> String { e.to_string() }`; every `(-32602, msg)` → `msg`; `other => Err(format!("unknown tool: {other}"))`; final wrap drops the tuple:

```rust
    Ok(match outcome {
        Ok(v) => json!({"content": [{"type": "text", "text": v.to_string()}]}),
        Err(msg) => json!({
            "content": [{"type": "text", "text": json!({"error": msg}).to_string()}],
            "isError": true
        }),
    })
```

Replace every `serde_json::to_value(x).unwrap()` with `serde_json::to_value(x).map_err(internal)?`. Use `clamp_wait_secs` in the `cmail_wait` arm and extend its description: `"... (default 30s, max 600s) ..."`.

protocol.rs `tools/call` arm adjusts to the new type: `tools::call(svc, as_name, &params).map_err(|msg| (-32603i64, msg))` — wait, tool errors are intentionally NOT JSON-RPC errors (they're isError results). Keep: `"tools/call" => Ok(tools::call(svc, as_name, &params)?)` — with `call` now infallible at the JSON-RPC layer (it returns `Result<Value, String>` handled internally), simplest is to change `call` to return `Value` directly and fold errors into the isError result internally. Choose: `pub fn call(svc, as_name, params) -> Value` (always a tool-result object); protocol arm becomes `"tools/call" => Ok(tools::call(svc, as_name, &params))`. Update the dispatch types accordingly.

- [ ] **Step 4: Run tests, commit**

Run: `cargo test -p cmail-mcp` then `cargo test --workspace` — all green.

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "fix(mcp): -32600 for missing method, 600s wait cap, String tool errors, full tool coverage tests (hardening)"
```

---

### Task H7: CLI polish and remaining test gaps

Closes: ledger T10/T11/T4/T9 minors (silent allow under --json, duplicated outcome strings, body XOR, no CLI-level spoof, trust 5th case, keyring conflict pin, attachment-limit tests).

**Files:**
- Modify: `crates/cmail-cli/src/commands/mail.rs`, `crates/cmail-cli/src/commands/admin.rs`, `crates/cmail-cli/tests/lifecycle.rs`, `crates/cmail-core/src/trust.rs`, `crates/cmail-core/src/keyring.rs`, `crates/cmail-core/src/envelope.rs` (tests only in the last three)

**Interfaces:**
- Produces: `mail.rs` gains `pub fn print_outcome(cli_json: bool, out: &SendOutcome)` used by send+reply; send errors when BOTH `--body` and `--body-file` given; `allow add/remove` print `{"status":"allowed"|"removed","name":...}` under `--json`.

- [ ] **Step 1: CLI behavior changes**

`mail.rs` — add the helper and use it from both `send` and `reply`:

```rust
pub fn print_outcome(json: bool, out: &SendOutcome) {
    if json {
        output::print_json(out);
        return;
    }
    match out {
        SendOutcome::Sent { id } => println!("sent ({id})"),
        SendOutcome::Held { id, to } => println!(
            "held for approval by {to} ({id}) — ask your human to run: cmail approvals"
        ),
    }
}
```

Body handling — replace the `(Some(b), _)` match with strict XOR:

```rust
    let body = match (body, body_file) {
        (Some(_), Some(_)) => bail!("provide --body or --body-file, not both"),
        (Some(b), None) => b,
        (None, Some(f)) => std::fs::read_to_string(&f).with_context(|| format!("reading {}", f.display()))?,
        (None, None) => bail!("provide --body or --body-file"),
    };
```

`admin.rs` `allow` — Add/Remove emit status:

```rust
        AllowCmd::Add { name } => {
            c.allow_add(&name)?;
            if cli.json {
                output::print_json(&serde_json::json!({"status": "allowed", "name": name}));
            } else {
                println!("allowed {name}");
            }
        }
        AllowCmd::Remove { name } => {
            c.allow_remove(&name)?;
            if cli.json {
                output::print_json(&serde_json::json!({"status": "removed", "name": name}));
            } else {
                println!("removed {name}");
            }
        }
```

- [ ] **Step 2: New/adjusted tests**

`trust.rs` (5th matrix case — precedence pin):

```rust
        // tampered envelope CLAIMING a keyring-known name, signed by an impostor:
        // signature check must win -> Invalid, not SpoofSuspect
        let (kr, _) = keyring_with("alice", &alice);
        let mut env = signed("alice", &mallory, "zoe");
        env.body = "tampered".into();
        assert_eq!(evaluate(&env, &kr).level, TrustLevel::Invalid);
```

`keyring.rs` (conflict pin):

```rust
    #[test]
    fn conflict_error_names_the_existing_fingerprint() {
        let mut kr = KeyRing::default();
        kr.add("alice", "YWxpY2VrZXk=").unwrap();
        let err = kr.add("alice", "bWFsbG9yeWtleQ==").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("different key"), "{msg}");
        assert!(msg.contains(&fingerprint_of("YWxpY2VrZXk=")), "must name the EXISTING key: {msg}");
    }
```

`envelope.rs` (size-limit tests):

```rust
    #[test]
    fn attachment_size_limits_enforced() {
        let (alice, _) = fixtures();
        let from_key = B64.encode(alice.verifying_key().as_bytes());
        let big = Attachment { filename: "big".into(), sha256: "0".repeat(64), size: MAX_ATTACHMENT_BYTES + 1 };
        let mut p = parts("alice", &from_key, "zoe");
        p.attachments = vec![big];
        assert!(build_and_sign("88".repeat(16).as_str(), &p, &alice).is_err());
        // total: 9 files of 3 MiB = 27 MiB > 25 MiB
        let mid = Attachment { filename: "m".into(), sha256: "0".repeat(64), size: 3 * 1024 * 1024 };
        let mut p = parts("alice", &from_key, "zoe");
        p.attachments = vec![mid; 9];
        assert!(build_and_sign("99".repeat(16).as_str(), &p, &alice).is_err());
    }
```

(`vec![mid; 9]` trips the count limit first — fine, the assertion is only that it errors; to specifically exercise the TOTAL limit use 3 files of 9 MiB = 27 MiB with count ≤ 8.)

`lifecycle.rs` — rename `spoof_lands_in_quarantine_never_inbox` → `corrupt_lands_in_quarantine_never_inbox` (it tampers a signature; the invalid path), and add a TRUE spoof test:

```rust
#[test]
fn true_spoof_lands_in_quarantine_never_inbox() {
    let root = TempDir::new().unwrap();
    cmail(&root).arg("init").arg("--name").arg("alice").assert().success();
    cmail(&root).arg("init").arg("--name").arg("zoe").assert().success();
    cmail(&root).arg("init").arg("--name").arg("mallory").assert().success();
    cmail(&root).arg("keyring").arg("add").arg("alice").assert().success(); // zoe's human trusts alice

    // Mallory signs an envelope claiming from: alice — self-consistent signature,
    // only the keyring comparison can catch it.
    use base64::Engine;
    let (owner, env) = {
        use cmail_core::identity::load_identity;
        use cmail_core::envelope::{build_and_sign, NewEnvelope};
        let mallory = load_identity(root.path(), "mallory").unwrap();
        let env = build_and_sign(
            &"ab".repeat(16),
            &NewEnvelope {
                from: "alice".into(),
                from_key: base64::engine::general_purpose::STANDARD.encode(mallory.signing.verifying_key().as_bytes()),
                to: "zoe".into(),
                kind: "note".into(),
                subject: "fake".into(),
                body: "imposter".into(),
                attachments: vec![],
                in_reply_to: None,
                created: "2026-11-01T12:00:00Z".into(),
            },
            &mallory.signing,
        )
        .unwrap();
        ("zoe", env)
    };
    std::fs::create_dir_all(root.path().join("mailboxes").join(&owner).join("inbox")).unwrap();
    std::fs::write(
        root.path().join("mailboxes").join(&owner).join("inbox").join(format!("{}.mail", env.id)),
        serde_json::to_string_pretty(&env).unwrap(),
    )
    .unwrap();

    let inbox = json_out(cmail(&root).arg("--as").arg("zoe").arg("--json").arg("inbox"));
    assert_eq!(inbox.as_array().map(Vec::len), Some(0));
    let q = json_out(cmail(&root).arg("--as").arg("zoe").arg("--json").arg("quarantine").arg("list"));
    assert_eq!(q.as_array().map(Vec::len), Some(1));
    assert_eq!(q[0]["from"], "alice");
}
```

(cmail-cli depends on cmail-core and serde_json already; `base64` is NOT a cli dependency — construct the b64 via `cmail_core::identity::load_identity(...).public_key_b64()` instead of encoding manually, dropping the base64 import.)

Also extend `full_lifecycle_with_json_shapes`: assert `allow add` now returns `{"status":"allowed","name":...}` under `--json`, and `send --body x --body-file y` exits 1 with an error.

- [ ] **Step 3: Run all tests, commit**

Run: `cargo test --workspace` — all green (update any test that asserted allow-add silence).

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "fix(cli+core): allow status JSON, strict body XOR, deduped outcome printer, true-spoof CLI test, matrix/conflict/limit pins (hardening)"
```

---

### Task H8: Docs truth pass and final verification

Closes: README drift from H6 behavior changes + final gate.

**Files:**
- Modify: `README.md`

**Interfaces:** none (docs + verification).

- [ ] **Step 1: README updates** — in "MCP protocol notes (honest edges)": add "a request missing `method` returns `-32600`; unknown methods return `-32601`" and "`cmail_wait` is capped at 600 s per call". In the quickstart: nothing changes. Confirm the human-only list still matches (`allow` still human-only). Double-check every command example in README/AGENTS.md still produces the shown shapes by running them on a fresh `--root target/h8`.

- [ ] **Step 2: Final gates**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: zero warnings, all tests green (baseline 50 + new tests from H1-H7; report the number).

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "docs: README truth pass for hardening changes"
```

---

## Self-review notes (applied while writing)

- H5's `send_gated` extraction preserves the Task-10 interface (`send` signature unchanged) — CLI/MCP untouched.
- H6's `call -> Value` shape change is internal to cmail-mcp; wire results identical.
- H4 `write_durable` tmp suffix (`.tmp`) matches the suffixes keyring/config/store already used — no collision risk change.
- Deliberately NOT done (still deferred, with reasons in the ledger): full-log-scan perf index for `was_released` (fine at v1 scale), fsync for ordinary mail reads, MCP batch support, retroactive `list --all` trust labels, cross-implementation canonical-JSON golden vectors (revisit with the first relay implementation).
