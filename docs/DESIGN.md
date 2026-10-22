# state.store: shared, encrypted app state on ce-net

> Written for the original engine. The Python tests and clients it names (`tests/*.py`, `clients/`) are not in this repository; `cargo test` runs the Rust engine and gate tests here.

**Status:** v1: Postgres hub plus SQLite light replicas, multi-master.

## 1. Why

Services kept their state in JSON files on disk (`sessions.json`, `people.json`, `rooms.json` and the like). Moving a
service to another machine meant copying those files by hand. Each file is plaintext on disk, has its own lock code,
its own permission check and no history, and two copies of one file can never merge.

The goal: one distributed, encrypted store that many services share with proper permissions, reached through an SDK
and typed clients in every language over authenticated ce-net transport, used every time a service needs state.

## 2. What it is

One service, `state.store` (service `ce.state.store`, ctl topic `state.store/ctl`).
Apps keep records in it as `(app, collection, key) -> JSON value`. It gives every app:

1. **Encryption at rest**: values are AES-256-GCM encrypted by the service before the database sees them.
2. **Encryption in transit**: clients only reach it over ce-net (libp2p Noise). Postgres listens on 127.0.0.1 only.
3. **Permissions**: every op needs a ce-cap chain naming `state.<app>.<collection>.<read|write|own>`, verified with
   `ce-iam verify --fail-closed` against the authenticated sender node. No passwords for clients.
4. **History**: every write gets a global sequence number; `changes(since)` replays them; an audit table hash-chains
   every write with the proven principal.
5. **A schema per app** (`schemas/<app>.json`) that the server validates writes against and that generates typed
   clients.
6. **Replication**: every machine runs a replica (Postgres on the hub, SQLite on a laptop); each accepts writes and
   pulls ciphertext from the others over ce-net, last writer wins by hybrid logical clock (section 7).

## 3. Choice of technology

| option | verdict | reason |
|---|---|---|
| **PostgreSQL** (bound to 127.0.0.1:5432) | **chosen** for the durable hub | decades of crash safety; logical replication built in; one process serves thousands of apps |
| rqlite (Raft SQLite) | rejected for v1 | another daemon and consensus cluster to run; Raft needs a majority online, a laptop fleet rarely has one |
| LiteFS / cr-sqlite | rejected for v1 | LiteFS needs FUSE and a single writer lease; cr-sqlite is CRDT SQLite and still pre-1.0 |
| an earlier LWW-per-field store (lamport ops, anti-entropy over ce-net) | idea taken, code not | its LWW-plus-anti-entropy model is what the replicas below do, but at record level with the same encryption, grants and audit as the hub |
| **SQLite 3** (in every Python, nothing to install) | **chosen** for light replicas | a laptop replica needs no daemon; the same store code runs on both backends |
| Postgres logical replication | rejected | single writer per row set, needs a TCP port between machines, and replicas would need Postgres; a laptop should run with nothing installed |
| pgcrypto `pgp_sym_encrypt` in SQL | rejected | the key would travel in SQL text and land in `pg_stat_statements` and server logs |
| Postgres row-level security | not needed in v1 | Postgres has one client (this service); permissions are enforced on the ce-cap chain before any SQL runs |

## 4. Threat model

| threat | what stops it |
|---|---|
| someone copies the Postgres data dir, a backup or a replica's disk | values are AES-256-GCM ciphertext; the key is `STATE_DB_DATA_KEY` in ce-key (Secret Service login keyring), never on disk in the clear |
| a stranger on the LAN or internet connects to Postgres | Postgres binds 127.0.0.1 (`listen_addresses = localhost`); role `state_store` has a generated scram password (`STATE_DB_PASSWORD` in ce-key); no `postgres/postgres` |
| a node on ce-net with no grant calls an op | ce-cap verify fails closed; test `tests/test_gate.py` shows a grant-less node refused |
| app A reads app B's records | actions are literal per app and collection (`state.workshow.sessions.read`); ce-iam matches literal strings and cannot mint wildcards |
| one person reads another person's rows | collections marked `per_person` scope keys to `<principal>/...` when the caller holds only `.own` |
| a copied ciphertext moved to another key | AES-GCM additional data is `app \0 collection \0 key`, so a value moved to another row fails to decrypt |
| a session token used as a record key leaks through listings, logs or the change feed | collections marked `hash_keys` store `HMAC-SHA256(app key, key)`; the real key exists only inside the ciphertext |
| a write nobody can attribute | `audit` table: one row per write with the ce-cap-proven principal, hash-chained (`hash = sha256(prev_hash ‖ row)`) |
| the keyring is locked after a reboot | on a server, `ce-key seal` copies the two keys into a sealed file that is decrypted into tmpfs at boot, so the store comes back unattended. A machine whose keyring cannot be reached headless (e.g. over ssh) reads `STATE_DB_DATA_KEY_FILE` instead (refused unless mode 600). Without either the service refuses to start and says why |
| a replica pulls without permission | `state.repl.pull` needs action `state.replica`, minted by the serving replica for the pulling node only (`ce-iam grant --action state.replica`) |
| a replica disk is stolen | it holds the same ciphertext as the hub; it decrypts only while its key file or keyring is present |
| a stolen grant | grants are minted with `--expires-in`; `ce-iam revoke` puts the nonce on chain; verdict cache is 30 s |

Out of scope for v1: a compromised root user on the hub (it can read the keyring of a logged-in session), traffic analysis of
the change feed (it carries app, collection, key or key hash, seq; never values).

## 5. Data model

```
records(app, coll, key, seq, version, value bytea, deleted, updated_at, updated_by)   PK (app, coll, key)
audit(id, at, app, coll, key, op, principal, seq, prev_hash, hash)
schemas(app, doc jsonb, updated_at, updated_by)
```

- `seq` comes from one global sequence: every write bumps it, so `list(since=seq)` and `changes(since)` page through
  writes in order.
- A delete is a tombstone (`deleted = true`, value NULL) so `changes` and replicas see it.
- `value` = `nonce(12) ‖ AES-GCM( {"k": key, "v": value} )` with the per-app key `HKDF(STATE_DB_DATA_KEY, "state.store/v1/<app>")`.

## 6. Wire (ce-net, JSON envelope `{op, args, cap}`)

| op | args | semantics |
|---|---|---|
| `state.get` | app, coll, key | the value, version, seq; `null` when absent |
| `state.put` | app, coll, key, value, if_version? | replace; with `if_version` it is compare-and-set (0 = must not exist) |
| `state.insert` | app, coll, key, value | idempotent create-if-absent; returns the existing record and `created: false` when present |
| `state.patch` | app, coll, key, fields | merge top-level fields into an object value |
| `state.delete` | app, coll, key | tombstone |
| `state.list` | app, coll, prefix?, since?, limit?, include_deleted? | records ordered by seq; `next` is the cursor |
| `state.changes` | app, coll, since | same as list with tombstones, for sync and replicas |
| `state.schema` | app | the registered schema |
| `state.schema.put` | app, schema | register or replace (action `state.<app>.admin`) |
| `state.health` | | Postgres reachable, key loaded, counts; no cap needed, reveals no data |

Every write publishes `{app, coll, key|key_hash, seq, version, op}` on pubsub `state.store/changes`.

**Actions.** `state.<app>.<coll>.read`, `.write`, `.own` (own rows of a `per_person` collection), `state.<app>.admin`.
App names are normalised to `[a-z0-9]` for actions (`work-show` -> `workshow`) because ce-iam action strings use `.` as
the separator. Mint with `bin/state-grant <node> <app> <coll> --read --write --expires-in <s>`.

## 7. Replication: every machine serves it together

No single machine serves the store alone: many machines serve it together, which is how it scales and how it
survives losing one.

Every machine runs one replica of `ce.state.store`. `STATE_STORE_DB` picks the backend: unset = local Postgres (the hub),
`sqlite:~/.local/share/state-store/state.db` = a light replica (e.g. a laptop). All replicas are equal: each accepts reads and
writes for its local apps.

| piece | how |
|---|---|
| ordering | every write carries `hlc` (hybrid logical clock: wall ms, counter) and `origin` (the writing node). The newer `(hlc, origin)` wins, the same on every replica |
| pull | `state.repl.pull(since, limit)` returns raw rows (ciphertext as base64, tombstones, schemas) after the caller's cursor, skipping rows that came from the caller |
| apply | `repl_apply` keeps a row only if its `(hlc, origin)` is newer than the local one; it writes an audit row (op `repl`) and moves the per-peer cursor in `repl_cursor` |
| trigger | a `state.store/changes` event from another node rings the doorbell; a 5 s timer (`STATE_STORE_PULL_EVERY`) is the fallback |
| relay | a row keeps its origin, so a write on replica A reaches replica B through the hub when A and B cannot see each other |
| grants | each replica's ce-iam trusts its own key, so a grant is honoured by the replica that minted it. Wallet labels: `state.store:replica@<server16>` for pulls, `state.store:<app>@<server16>` for app ops, `state.store:<app>` = the hub default |
| client routing | the client asks this machine's replica first, sticks to the one that answers (so `since` cursors stay on one sequence), and moves on after a refusal that proves nothing was written (no grant there, no schema yet) or a dead replica; a `tries=1` write is never sent twice after a timeout |

Measured in `tests/test_replication.py` (Postgres hub + two SQLite replicas): a write on any replica reaches all,
concurrent writes to one key settle on the same value everywhere, a write relays through the hub with the direct link
down, a delete arrives as a tombstone, a replica offline for 5 writes catches up from its cursor, a pull without the
replica grant is refused, and every audit chain verifies.

Later stages: shard apps across
hubs by a signed map when one hub is not enough; one account root (`ce-iam account`) so a grant is honoured fleet-wide
instead of per replica.

## 8. SDK and typed clients

The schema is the source of truth. `schemas/<app>.json`:

```json
{"app": "my-app", "collections": {
  "people": {"key": "person id", "value": {"type": "object", "properties": {"name": {"type": "string"}}}},
  "shares": {"value": {"type": "object"}, "per_person": false}
}}
```

`bin/state-gen` reads every schema and writes typed clients:

| language | transport | status |
|---|---|---|
| Python | `clients/python/state_store` over `ce-py` (stdlib only) | **v1** |
| TypeScript | `clients/ts` over the local node HTTP API (`/discovery/find`, `/mesh/request`) | **v1** |
| Rust | over `ce-rs` | generator next |
| Go | over `ce-go` | generator next |
| Swift | over the node HTTP API | generator next |

Every client authenticates the same way: the local ce node signs the transport, the client sends a ce-cap chain from
`$STATE_STORE_CAP` or the ce-iam wallet (label `state.store:<app>@<replica16>`, then `state.store:<app>`, then
`state.store`). `state_store.enabled()` reads `STATE_STORE=1`, the cutover switch for an app moving off its JSON file. No client holds a database
password and no client sees a database port.

Swapping a JSON file for state.store is two lines:

```python
from state_store import Doc
people = Doc("my-app", "people")           # was: json.load(open("people.json"))
data = people.load(); ...; people.save(data)   # save writes only the changed keys
```

## 9. Migrating an app off JSON files

Load a JSON object (one record per top-level key) or a JSONL file into a collection with the client (`Doc(...).save`
or `collection.put` per record), then switch the app's code to `Doc(...)`. Secrets found next to such files
(passwords, cookie secrets, API tokens) are not state: they go in a secret store such as ce-key.

## 10. Verification

`tests/` runs against the live Postgres in a throwaway database: encryption round trip and tamper refusal, AAD binding,
hashed keys, CAS and idempotent insert, the cap gate refusing a grant-less node and a wrong-app grant, `per_person`
scoping, audit chain integrity, codegen output compiling (Python import, `tsc --noEmit`). `tests/test_gate.py` uses the
real ce-iam; `tests/test_replication.py` the three-replica cluster above; `tests/test_e2e.py` and
`clients/ts/e2e.mjs` the running service over ce-net (watch latency 33 to 290 ms).
