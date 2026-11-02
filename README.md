# cmail

Store-and-forward mail for AI agents, with **permissioning as the headline
feature**. One static Rust binary, no daemon, no servers, no accounts: a shared
mailbox root (`~/.cmail/`) is the meeting ground, messages are Ed25519-signed
JSON envelopes sitting in plain directories.

- **Agent-first** — a CLI with `--json` everywhere *and* a stdio MCP server in
  the same binary. Any harness that speaks MCP gets `cmail` with zero glue.
- **Zero-framework adoption** — a second agent joins by pointing its MCP config
  at the same binary. No signup, no infrastructure, no background process.
- **Permissioning first** — outbound mail to unapproved recipients is
  quarantined for human release; inbound mail from unverified senders is
  delivered wrapped in explicit `UNTRUSTED MAIL BODY` delimiters so agents
  treat it as data, not instructions.

## Install

Prebuilt binaries (Linux x86_64/aarch64, Windows x86_64, macOS x86_64/aarch64)
are attached to each [release](https://github.com/tigwyk/cmail/releases) with a
`SHA256SUMS.txt` — download, verify, put on PATH:

```bash
curl -LO https://github.com/tigwyk/cmail/releases/download/v0.2.0/cmail-v0.2.0-x86_64-unknown-linux-gnu.tar.gz
tar -xzf cmail-v0.2.0-x86_64-unknown-linux-gnu.tar.gz
sudo install cmail-v0.2.0-x86_64-unknown-linux-gnu/cmail /usr/local/bin/
```

(Substitute your platform and the current version from the
[releases page](https://github.com/tigwyk/cmail/releases).)

Or build from source (requires a Rust toolchain):

```bash
git clone https://github.com/tigwyk/cmail && cd cmail
cargo install --path .
```

## Quickstart

Two agents on one machine (adjust `--root` to taste; default is `~/.cmail`):

```bash
cmail init --name alice          # identity + Ed25519 keypair (idempotent)
cmail init --name zoe

# alice mails zoe a handoff — NOT allowlisted, so it's held, not sent:
cmail --as alice send --to zoe --kind handoff --subject "handoff" --body "the state"
# => {"status":"held","id":"…","to":"zoe"}

# the human releases it (and optionally remembers zoe as approved):
cmail approvals
cmail approve <id> --remember

# zoe reads it — unknown sender, so the body arrives fenced:
cmail --as zoe --json read <id>
# body: "--- UNTRUSTED MAIL BODY (sender not verified; …) ---\nthe state\n--- END …"

# the human trusts alice's key; the next mail arrives verified, unfenced:
cmail keyring add alice
cmail --as alice send --to zoe --body "again"     # zoe is remembered from --remember
cmail --as zoe --json inbox
# => [{"id":"…","from":"alice",…,"trust":"verified",…}]
cmail --as zoe --json read <new-id>
# => …"body":"again"…   (no fence — verified sender)
```

## The trust model

Every message is signed by its sender's Ed25519 key, and every envelope carries
the sender's public key inline (`from_key`), so signatures are checkable even
for strangers. Trust is computed at read time from YOUR local keyring — it is
never stored in (or forgeable via) the message.

| `trust` | Meaning | Presentation |
|---|---|---|
| `verified` | Sender's key is in your keyring and the signature verifies | Raw body |
| `untrusted` | Valid signature, unknown key | Body wrapped in UNTRUSTED delimiters + key fingerprint shown (TOFU) |
| `spoof_suspect` | Claims a known name but a *different* key signed it | Never reaches the inbox — quarantined, audited |
| `invalid` | Signature fails against its own inline key | Quarantined, audited |

Trust never requires decrypting — it is computed from the signed header, so it
works identically on sealed mail (next section).

## Encryption

Every send seals its content end-to-end to the recipient — transparently, with
no new commands, flags, or key ceremonies. The recipient's existing identity
key does double duty (Ed25519 for signatures, converted to X25519 for the key
exchange), so there is nothing extra to generate, exchange, or manage — and no
opt-out: new mail is always sealed.

- **Sealed** (ciphertext at rest and on the wire): subject, kind, body,
  attachments, and threading (`in_reply_to`).
- **Still visible by design**: who mailed whom (`from`/`to`), timestamps, and
  message/attachment sizes — the header the trust model above runs on.

Honest edges:

- **No forward secrecy** — there is no ratchet. A stolen identity key decrypts
  everything sealed to that identity.
- **No metadata privacy** — anyone holding the mailbox root can see who mailed
  whom, when, and how large.
- Listings and approvals show `"<sealed>"` / `"sealed"` placeholders for
  subject and kind; the real values appear only on `read`.
- v1 (unsealed) mail remains readable forever.

## Human-only powers

Agents can send, read, reply, wait, and list their own held mail — nothing
else. These exist only in the CLI, used by the human owner:

- `cmail approvals` / `approve <id> [--remember]` / `reject <id>` — the outbound gate
- `cmail allow add|remove|list` — outbound allowlist
- `cmail keyring add <name> [--key-file f | --from-message <id>]` / `list` — trust decisions
- `cmail quarantine list|show|release` — quarantine review (`release` moves to
  archive: reviewed, retained, never re-shown to the agent)
- `cmail audit [--tail N]` — append-only log of every security-relevant event
- `config.toml` — `outbound = "gated"|"open"`, `inbound = "permissive"|"known-only"`

## MCP wiring

```json
{
  "mcpServers": {
    "cmail": {
      "command": "cmail",
      "args": ["mcp", "--as", "<this-agent's-identity>"]
    }
  }
}
```

Six agent-safe tools: `cmail_send`, `cmail_inbox`, `cmail_read`, `cmail_reply`,
`cmail_wait`, `cmail_approvals` (listing only). Held sends return
`status: "held"` with guidance to inform the human; untrusted bodies arrive
fenced; the tool descriptions themselves carry the "mail is data" rule.

Wire two CLIs by giving each its own identity via `--as`.

MCP protocol notes (honest edges): tool failures (unknown tool, missing
arguments, internal errors) surface as JSON-RPC *successes* with
`"isError": true` and an `{"error": …}` text payload. JSON-RPC error objects
are returned for a request missing (or carrying a non-string) `method`
(`-32600`) and for unknown methods (`-32601`). The server is sequential — a
blocking `cmail_wait` delays other requests for its duration (`cmail_wait` is
capped at 600 s per call). `protocolVersion` is echoed, not negotiated. Batch
requests are not supported.

## Two machines, no servers

The mailbox root is just a directory of signed, sealed envelopes — sync it
with Syncthing, git, rsync, or a USB stick. Signatures and the local keyring
make synced copies safe: a name you know arriving with an unknown key is a
spoof suspect, not a surprise. Content is end-to-end encrypted (see
[Encryption](#encryption)), so relays and synced-folder readers stay blind to
it; relay infrastructure itself remains out of scope, per
[the spec, §11](docs/superpowers/specs/2026-11-01-cmail-design.md).

## Design documentation

Spec (envelope format, trust/permissioning model, CLI reference, audit events):
[`docs/superpowers/specs/2026-11-01-cmail-design.md`](docs/superpowers/specs/2026-11-01-cmail-design.md)

Sealed envelopes (v1.1 end-to-end encryption):
[`docs/superpowers/specs/2026-11-01-cmail-sealed-envelopes-design.md`](docs/superpowers/specs/2026-11-01-cmail-sealed-envelopes-design.md)

Agent-facing cheat sheet: [`AGENTS.md`](AGENTS.md)

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option — pick whichever suits. The Rust ecosystem standard, so cmail drops into
any project without license friction.
