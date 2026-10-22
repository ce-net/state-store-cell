# state.store cell (Rust)

The typed ce-wire front door of state.store, plus its storage engine in Rust. The engine started as a Python server; this
port reads and writes the same tables and byte formats, so rows written by either decrypt in the other. The Python
engine is not published. Two crates:

- `crates/state-store-api`: the typed API (types only, plus a blocking client `state_store_api::Docs`).
- `crates/state-store`: the cell binary (serves the API and the legacy JSON topic) and a CLI client.

## Ops (`crates/state-store-api`, api `state.store` v2)

| op | in -> out | right (Hello) |
|---|---|---|
| 1 Get | `GetReq{at,key,cap}` -> `Option<Doc>` | `state.store:read` |
| 2 Put | `PutReq{at,key,value(JSON text),if_version,insert_only,cap}` -> `Doc`; `if_version` Some(v) = compare-and-set, Some(0) = create only | `state.store:write` |
| 3 Delete | `DeleteReq{at,key,cap}` -> `()` (tombstone) | `state.store:write` |
| 4 List | `ListReq{at,prefix,since,limit,include_deleted,cap}` -> `Page{docs,next}` in seq order | `state.store:read` |
| 5 Health | `()` -> `StoreHealth` | `state.store:read` |
| 7 Patch | merge top-level fields | `state.store:write` |
| 8/9 Schema, SchemaPut | read / register an app schema (`state.<app>.admin`) | read / write |
| 6 Watch (stream) | `WatchReq{at,since,cap}` -> `Doc`s (tombstones included), then each new change | `state.store:read` |

Two checks per call: the Hello proves which node calls (right above); `cap` (the hex chain `ce-iam wallet show
state.store:<app>@<node16>` prints) must grant `state.<app>.<coll>.read|write|own` to that node. Limits live in the api
crate: name `[A-Za-z0-9._-]{1,64}`, key <= 512 B, value <= 2000 B (slow long-distance mesh links drop larger messages), page <= 500. Blocking
client: `state_store_api::Docs::new(client, app, coll, cap)` (`load` / `save` with CAS / `remove` / `list`).

## Engine parity with the original Python engine

| python | Rust |
|---|---|
| `Store` ops get/put/insert/patch/delete/list/changes/schema/schema.put/health | `engine.rs`, same arguments and reply shapes, same error texts |
| HLC (hybrid logical clock) | `Store::now/observe`, `{wall_ms:013}-{counter:06}` |
| hash-chained audit, `sha256(json.dumps([prev,app,coll,key,op,principal,seq]))` | `py_audit_json` reproduces Python's `json.dumps` bytes (ensure_ascii, `", "`); `state-store verify` checks the whole chain |
| AES-256-GCM rows, HKDF-SHA256 `state.store/v1/<app>` per-app key, AAD `app\0coll\0key`, HMAC key hashing | same crates' output byte for byte; rows written by either engine decrypt in the other |
| `state.repl.pull/since/push` + `repl_cursor` | same ops, same page/byte budgets, same last-writer-wins on `(hlc, origin)` |
| `Replicator` loop, 5 s + bell from `state.store/changes` | `mesh::replicate`, per-peer adaptive page size |
| ce-iam verify subprocess | `auth.rs`: `ce_cap::authorize` rooted at this node's key only, revocations file honoured, fail closed |
| `ce.serve_app` on topic `state.store/ctl` | `mesh::serve_legacy`: SSE from the node, 8 workers, bounded queue, replies by token |

Two doors, one engine: the typed ce-wire API `state.store` v2 (every request carries `cap`, the hex grant checked per
`state.<app>.<coll>.<verb>` against the caller's authenticated node) and the legacy JSON topic, so the Python client
(`from state_store import Doc`) and Python replicas keep working unchanged. Rows written by either engine are readable
by the other.

Postgres transactions take `pg_advisory_xact_lock(7001)` (the Python server takes the same lock), so two writers cannot
fork the audit chain. `state-store verify` checks the whole chain and exits non-zero when the number of breaks is above
`STATE_STORE_AUDIT_BASELINE` (default 0); set a baseline only for a database that holds breaks written before that lock
existed.

Not yet: per-caller `per_person` scoping on the typed path uses the node id as the caller (same as the legacy path);
Watch polls every 300 ms instead of riding the change feed.

## Configuration

| setting | meaning |
|---|---|
| `STATE_STORE_LEGACY=0` (or `~/.config/ce-state/legacy` holding `0`) | turn off the legacy JSON topic and replicator, e.g. where the Python server already serves them |
| `STATE_STORE_NODE_NAMES` (default `~/.config/ce-state/node-names`) | lines `<64-hex node id> <name> [<alias>...]` for a schema's `replicas` list |
| `STATE_STORE_PULL_EVERY` | replication fallback timer in seconds (default 5) |

## Build and run

The crates depend on `ce-wire` and `ce-gate` from https://github.com/ce-net/ce-door (see `Cargo.toml`).

```
cargo build --release
cargo test
state-store health
state-store put APP COLL KEY JSON [version] | get APP COLL KEY | list APP COLL [prefix] | del APP COLL KEY
CE_DATA_DIR=$(mktemp -d) state-store get notes notes x    # a node with no grant: refused
```

Expected: a stale `version` is refused (`version conflict`); a node with no grant is refused (`capability chain does
not root at an accepted authority`); a value over 2000 B is refused by the cell; an app with no grant is refused by the
store.
