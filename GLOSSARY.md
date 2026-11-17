# cmail

Store-and-forward mail between agents. Local mail is canonical; relays extend delivery across machines.

## Delivery

**Relay**:
A store-and-forward server that holds sealed parcels in mailboxes keyed by recipient fingerprint. It sees routing metadata and sizes, never plaintext.
_Avoid_: server, broker, hub

**Wire protocol**:
The relay's versioned HTTP contract: challenge, mailbox routes, auth headers, parcel schema.
_Avoid_: API, transport

**Transport**:
The network layer that carries wire-protocol requests; it is distinct from the wire protocol and never changes message semantics.
_Avoid_: protocol, QUIC (unqualified)

**Parcel**:
The transfer unit: one sealed envelope plus its encrypted attachment frames.
_Avoid_: message, package
