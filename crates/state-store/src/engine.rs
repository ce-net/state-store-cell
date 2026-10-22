//! The state.store engine: a port of python `server/store.py` onto the same tables and the same byte formats
//! (AES-256-GCM rows, HKDF per-app keys, hash-chained audit, HLC stamps, replication rows), so the two can share one
//! database during the migration and either can verify the other's audit chain.
use crate::auth::Auth;
use crate::db::{Db, Tx, V};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

pub const MAX_VALUE: usize = 4 * 1024 * 1024;
pub const REPL_BYTES: usize = 64 * 1024;
pub const MAX_LIMIT: i64 = 1000;
pub const REPLICA_ACTION: &str = "state.replica";

pub type R<T> = Result<T, String>;

pub struct Store {
    pub db: Db,
    master: Vec<u8>,
    auth: Auth,
    pub node_id: String,
    on_change: Box<dyn Fn(Value) + Send + Sync>,
    clock: Mutex<(i64, i64)>,
    keys: Mutex<HashMap<String, [u8; 32]>>,
    /// app -> (read at, schema): every op reads its app's schema, so it is cached for [`SCHEMA_TTL`] (another
    /// server on the same database may change it; a schema write here clears the cache at once).
    schemas: Mutex<HashMap<String, (std::time::Instant, Option<Value>)>>,
    /// node id -> its names, for a schema's `replicas` list ([`load_node_names`]).
    pub names: HashMap<String, Vec<String>>,
}

/// `{node id: names}` from the node-names file (`$STATE_STORE_NODE_NAMES`, else `~/.config/ce-state/node-names`; lines
/// `<64-hex node id> <name> [<alias>...]`, `#` comments), plus this node's own name from `~/.config/ce-wire/name`
/// (`$CE_WIRE_NAME_FILE`). A missing file is no names: a `replicas` list then matches node ids only (fail closed).
/// The same file and format as python `server/store.py load_node_names`.
pub fn load_node_names(path: &std::path::Path, own_id: &str, own_name_file: &std::path::Path) -> HashMap<String, Vec<String>> {
    let mut names: HashMap<String, Vec<String>> = HashMap::new();
    for line in std::fs::read_to_string(path).unwrap_or_default().lines() {
        let w: Vec<&str> = line.split('#').next().unwrap_or("").split_whitespace().collect();
        if w.len() >= 2 {
            names.entry(w[0].to_string()).or_default().extend(w[1..].iter().map(|n| n.to_string()));
        }
    }
    if let Some(n) = std::fs::read_to_string(own_name_file).ok().map(|n| n.trim().to_string()).filter(|n| !n.is_empty() && !own_id.is_empty()) {
        names.entry(own_id.to_string()).or_default().push(n);
    }
    names
}

fn default_node_names(own_id: &str) -> HashMap<String, Vec<String>> {
    let home = std::env::var("HOME").unwrap_or_default();
    let path = std::env::var("STATE_STORE_NODE_NAMES").unwrap_or_else(|_| format!("{home}/.config/ce-state/node-names"));
    let own = std::env::var("CE_WIRE_NAME_FILE").unwrap_or_else(|_| format!("{home}/.config/ce-wire/name"));
    load_node_names(path.as_ref(), own_id, own.as_ref())
}

/// How long a cached schema is trusted: the longest another writer's schema change takes to be seen here.
const SCHEMA_TTL: std::time::Duration = std::time::Duration::from_secs(5);

fn name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 64 && b[0].is_ascii_alphanumeric() && b.iter().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(c))
}

fn action_name(s: &str) -> String {
    s.to_lowercase().chars().filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit()).collect()
}
pub fn action(app: &str, coll: Option<&str>, verb: &str) -> String {
    match coll {
        Some(c) => format!("state.{}.{}.{verb}", action_name(app), action_name(c)),
        None => format!("state.{}.{verb}", action_name(app)),
    }
}

/// Python `json.dumps` of a list of strings and one int, byte for byte (ensure_ascii, ", " separators).
pub fn py_audit_json(strs: &[&str], seq: i64) -> String {
    let mut o = String::from("[");
    for s in strs {
        o.push('"');
        for ch in s.chars() {
            match ch {
                '"' => o.push_str("\\\""),
                '\\' => o.push_str("\\\\"),
                '\n' => o.push_str("\\n"),
                '\r' => o.push_str("\\r"),
                '\t' => o.push_str("\\t"),
                '\u{8}' => o.push_str("\\b"),
                '\u{c}' => o.push_str("\\f"),
                ' '..='~' => o.push(ch),
                c => {
                    let mut b = [0u16; 2];
                    for u in c.encode_utf16(&mut b) {
                        o.push_str(&format!("\\u{:04x}", u));
                    }
                }
            }
        }
        o.push_str("\", ");
    }
    o.push_str(&seq.to_string());
    o.push(']');
    o
}

fn sha_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}
fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
fn s<'a>(a: &'a Value, k: &str) -> Option<&'a str> {
    a.get(k).and_then(Value::as_str)
}

// ---- schema validation: the JSON Schema subset the generators understand ----
pub fn validate(value: &Value, schema: &Value, path: &str) -> R<()> {
    let Some(sc) = schema.as_object().filter(|o| !o.is_empty()) else { return Ok(()) };
    if let Some(t) = sc.get("type") {
        let types: Vec<&str> = match t {
            Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
            Value::String(x) => vec![x.as_str()],
            _ => vec![],
        };
        let ok = types.iter().any(|one| match *one {
            "integer" => value.is_i64() || value.is_u64(),
            "number" => value.is_number(),
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => false,
        });
        if !ok {
            return Err(format!("{path}: expected {t}"));
        }
    }
    if let Some(e) = sc.get("enum").and_then(Value::as_array) {
        if !e.contains(value) {
            return Err(format!("{path}: not one of {}", Value::Array(e.clone())));
        }
    }
    if let Some(obj) = value.as_object() {
        for r in sc.get("required").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
            if !obj.contains_key(r) {
                return Err(format!("{path}.{r}: required"));
            }
        }
        let props = sc.get("properties").and_then(Value::as_object);
        for (k, v) in obj {
            if let Some(p) = props.and_then(|p| p.get(k)) {
                validate(v, p, &format!("{path}.{k}"))?;
            } else if sc.get("additionalProperties") == Some(&Value::Bool(false)) {
                return Err(format!("{path}.{k}: not in schema"));
            } else if let Some(ap) = sc.get("additionalProperties").filter(|x| x.is_object()) {
                validate(v, ap, &format!("{path}.{k}"))?;
            }
        }
    }
    if let (Some(arr), Some(items)) = (value.as_array(), sc.get("items").filter(|x| x.is_object())) {
        for (i, v) in arr.iter().enumerate() {
            validate(v, items, &format!("{path}[{i}]"))?;
        }
    }
    Ok(())
}

impl Store {
    pub fn new(db: Db, master: Vec<u8>, auth: Auth, node_id: String, on_change: Box<dyn Fn(Value) + Send + Sync>) -> R<Store> {
        let names = default_node_names(&node_id);
        let st = Store { db, master, auth, node_id, on_change, clock: Mutex::new((0, 0)), keys: Mutex::default(), schemas: Mutex::default(), names };
        if let Some(h) = st.db.q("SELECT max(hlc) FROM records", &[])?.first().and_then(|r| r.first()).map(V::s).filter(|h| !h.is_empty()) {
            st.observe(&h);
        }
        Ok(st)
    }

    // ---- hybrid logical clock ----
    pub fn now(&self) -> String {
        let mut g = self.clock.lock().unwrap();
        let wall = now_ms();
        if wall > g.0 {
            *g = (wall, 0);
        } else {
            g.1 += 1;
        }
        format!("{:013}-{:06}", g.0, g.1)
    }
    pub fn observe(&self, h: &str) {
        let Some((a, b)) = h.split_once('-') else { return };
        let (Ok(rl), Ok(rc)) = (a.parse::<i64>(), b.parse::<i64>()) else { return };
        let mut g = self.clock.lock().unwrap();
        let m = g.0.max(rl).max(now_ms());
        if m == g.0 && m == rl {
            g.1 = g.1.max(rc) + 1;
        } else if m == g.0 {
            g.1 += 1;
        } else if m == rl {
            g.1 = rc + 1;
        } else {
            g.1 = 0;
        }
        g.0 = m;
    }

    // ---- crypto ----
    fn app_key(&self, app: &str) -> [u8; 32] {
        let mut k = self.keys.lock().unwrap();
        *k.entry(app.into()).or_insert_with(|| {
            let mut o = [0u8; 32];
            hkdf::Hkdf::<Sha256>::new(None, &self.master).expand(format!("state.store/v1/{app}").as_bytes(), &mut o).expect("hkdf 32");
            o
        })
    }
    fn aad(app: &str, coll: &str, key: &str) -> Vec<u8> {
        format!("{app}\0{coll}\0{key}").into_bytes()
    }
    fn seal(&self, app: &str, coll: &str, skey: &str, key: &str, value: &Value) -> R<Vec<u8>> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;
        let blob = serde_json::to_vec(&json!({"k": key, "v": value})).map_err(|e| e.to_string())?;
        let c = Aes256Gcm::new(&self.app_key(app).into());
        let ct = c.encrypt(Nonce::from_slice(&nonce), Payload { msg: &blob, aad: &Self::aad(app, coll, skey) }).map_err(|e| e.to_string())?;
        Ok([nonce.to_vec(), ct].concat())
    }
    fn open(&self, app: &str, coll: &str, skey: &str, data: &[u8]) -> R<Value> {
        if data.len() < 28 {
            return Err("row too short".into());
        }
        let c = Aes256Gcm::new(&self.app_key(app).into());
        let blob = c
            .decrypt(Nonce::from_slice(&data[..12]), Payload { msg: &data[12..], aad: &Self::aad(app, coll, skey) })
            .map_err(|_| "row does not decrypt (wrong key or moved row)".to_string())?;
        serde_json::from_slice(&blob).map_err(|e| e.to_string())
    }

    // ---- schema ----
    pub fn schema(&self, app: &str) -> R<Option<Value>> {
        if let Some((at, sc)) = self.schemas.lock().unwrap().get(app) {
            if at.elapsed() < SCHEMA_TTL {
                return Ok(sc.clone());
            }
        }
        let sc = self.db.q("SELECT doc FROM schemas WHERE app=?", &[app.into()])?.first().map(|r| r[0].json());
        self.schemas.lock().unwrap().insert(app.to_string(), (std::time::Instant::now(), sc.clone()));
        Ok(sc)
    }
    /// May `node` (a node id, or a name when the id is unknown) hold rows of `app`? A schema's `replicas` list (node ids
    /// or names) keeps an app's rows on the nodes it names (e.g. EU residency); no list =
    /// every replica. `None` = an unknown receiver: never.
    pub fn replica_ok(&self, app: &str, node: Option<&str>) -> R<bool> {
        let Some(reps) = self.schema(app)?.and_then(|s| s.get("replicas").cloned()) else { return Ok(true) };
        let Some(node) = node.filter(|n| !n.is_empty()) else { return Ok(false) };
        let listed = |n: &str| reps.as_array().is_some_and(|a| a.iter().any(|r| r.as_str() == Some(n)));
        Ok(listed(node) || self.names.get(node).is_some_and(|ns| ns.iter().any(|n| listed(n))))
    }

    fn coll_schema(&self, app: &str, coll: &str) -> R<Value> {
        let Some(sc) = self.schema(app)? else { return Err(format!("app '{app}' has no schema; register one with state.schema.put")) };
        sc.get("collections").and_then(|c| c.get(coll)).cloned().ok_or_else(|| format!("collection {app}/{coll} is not in the schema"))
    }
    fn stored_key(&self, app: &str, coll: &str, key: &str, cs: &Value) -> String {
        if cs.get("hash_keys").is_some_and(|v| v.as_bool() == Some(true) || (!v.is_null() && v != &Value::Bool(false))) {
            let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&self.app_key(app)).expect("hmac key");
            m.update(format!("{coll}\0{key}").as_bytes());
            m.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
        } else {
            key.into()
        }
    }

    // ---- the gate: Ok("all"|"own") ----
    fn gate(&self, app: Option<&str>, coll: Option<&str>, verb: &str, cap: Option<&str>, sender: &str) -> R<&'static str> {
        for (n, v) in [("app", app), ("coll", coll)] {
            if let Some(v) = v {
                if !name_ok(v) {
                    return Err(format!("bad {n}"));
                }
            }
        }
        let Some(app) = app else { return Err("bad app".into()) };
        if sender.is_empty() {
            return Err("no authenticated sender".into());
        }
        if self.auth.ok(cap, &action(app, coll, verb), sender) {
            return Ok("all");
        }
        if coll.is_some() && (verb == "read" || verb == "write") && self.auth.ok(cap, &action(app, coll, "own"), sender) {
            return Ok("own");
        }
        Err(format!("not authorized: {}", action(app, coll, verb)))
    }
    fn can(&self, app: &str, coll: Option<&str>, verb: &str, cap: Option<&str>, sender: &str) -> bool {
        self.gate(Some(app), coll, verb, cap, sender).is_ok()
    }
    fn scoped_key(&self, key: Option<&str>, scope: &str, cs: &Value, sender: &str) -> R<String> {
        let Some(key) = key.filter(|k| !k.is_empty() && k.len() <= 512) else { return Err("bad key".into()) };
        if scope == "own" {
            if cs.get("per_person").and_then(Value::as_bool) != Some(true) {
                return Err("collection is not per_person".into());
            }
            return Ok(format!("{sender}/{key}"));
        }
        Ok(key.into())
    }

    fn audit(&self, t: &mut Tx, app: &str, coll: &str, skey: &str, op: &str, principal: &str, seq: i64) -> R<()> {
        let prev = t.q("SELECT hash FROM audit ORDER BY id DESC LIMIT 1", &[])?.first().map(|r| r[0].s()).unwrap_or_else(|| "0".repeat(64));
        let h = sha_hex(&py_audit_json(&[&prev, app, coll, skey, op, principal], seq));
        t.q(
            "INSERT INTO audit(at,app,coll,key,op,principal,seq,prev_hash,hash) VALUES ({TS},?,?,?,?,?,?,?,?)",
            &[app.into(), coll.into(), skey.into(), op.into(), principal.into(), seq.into(), prev.into(), h.into()],
        )?;
        Ok(())
    }

    fn record(&self, app: &str, coll: &str, row: &[V], cs: &Value) -> R<Value> {
        let (skey, seq, version, value, deleted) = (row[0].s(), row[1].i(), row[2].i(), &row[3], row[4].flag());
        let mut out = json!({"seq": seq, "version": version, "deleted": deleted});
        if let Some(v) = value.b() {
            let env = self.open(app, coll, &skey, &v)?;
            out["key"] = env["k"].clone();
            out["value"] = env["v"].clone();
        } else {
            out["key"] = if cs.get("hash_keys").is_some_and(|v| v != &Value::Bool(false) && !v.is_null()) { Value::Null } else { json!(skey) };
        }
        Ok(out)
    }

    fn event(&self, app: &str, coll: &str, skey: &str, cs: &Value, seq: i64, version: i64, op: &str) {
        let hk = cs.get("hash_keys").is_some_and(|v| v != &Value::Bool(false) && !v.is_null());
        let mut ev = json!({"app": app, "coll": coll, "seq": seq, "version": version, "op": op, "node": self.node_id});
        // the event is published on the mesh changes topic: a residency app's keys (tenant|person) never go there
        if self.schema(app).ok().flatten().is_none_or(|s| s.get("replicas").is_none()) {
            ev[if hk { "key_hash" } else { "key" }] = json!(skey);
        }
        (self.on_change)(ev);
    }

    #[allow(clippy::too_many_arguments)]
    fn upsert(&self, t: &mut Tx, app: &str, coll: &str, skey: &str, seq: i64, version: i64, sealed: Option<Vec<u8>>, by: &str, hlc: &str, origin: &str) -> R<()> {
        let deleted = sealed.is_none();
        t.q(
            "INSERT INTO records(app,coll,key,seq,version,value,deleted,updated_at,updated_by,hlc,origin) VALUES (?,?,?,?,?,?,?,{TS},?,?,?) \
             ON CONFLICT (app,coll,key) DO UPDATE SET seq=EXCLUDED.seq, version=EXCLUDED.version, value=EXCLUDED.value, deleted=EXCLUDED.deleted, \
             updated_at=EXCLUDED.updated_at, updated_by=EXCLUDED.updated_by, hlc=EXCLUDED.hlc, origin=EXCLUDED.origin",
            &[app.into(), coll.into(), skey.into(), seq.into(), version.into(), sealed.map_or(V::Null, V::B), V::Bool(deleted), by.into(), hlc.into(), origin.into()],
        )?;
        Ok(())
    }

    // ---- ops ----
    pub fn get(&self, a: &Value, cap: Option<&str>, sender: &str) -> R<Value> {
        let (app, coll) = (s(a, "app"), s(a, "coll"));
        let scope = self.gate(app, coll, "read", cap, sender)?;
        let (app, coll) = (app.unwrap(), coll.unwrap_or(""));
        let cs = self.coll_schema(app, coll)?;
        let key = self.scoped_key(s(a, "key"), scope, &cs, sender)?;
        let rows = self.db.q(
            "SELECT key,seq,version,value,deleted FROM records WHERE app=? AND coll=? AND key=?",
            &[app.into(), coll.into(), self.stored_key(app, coll, &key, &cs).into()],
        )?;
        match rows.first() {
            Some(r) if !r[4].flag() => self.record(app, coll, r, &cs),
            _ => Ok(Value::Null),
        }
    }

    fn write(&self, a: &Value, cap: Option<&str>, sender: &str, op: &str) -> R<Value> {
        let (app, coll) = (s(a, "app"), s(a, "coll"));
        let scope = self.gate(app, coll, "write", cap, sender)?;
        let (app, coll) = (app.unwrap(), coll.unwrap_or(""));
        let cs = self.coll_schema(app, coll)?;
        if !self.replica_ok(app, Some(&self.node_id))? {
            let reps = self.schema(app)?.and_then(|s| s.get("replicas").cloned()).unwrap_or(Value::Null);
            return Err(format!("app '{app}' keeps its rows only on replicas {reps}; this node ({}) is not one of them", &self.node_id[..16.min(self.node_id.len())]));
        }
        let key = self.scoped_key(s(a, "key"), scope, &cs, sender)?;
        let skey = self.stored_key(app, coll, &key, &cs);
        let (res, seq, nv) = self.db.tx(|t| {
            let rows = t.q(
                "SELECT key,seq,version,value,deleted FROM records WHERE app=? AND coll=? AND key=? FOR UPDATE",
                &[app.into(), coll.into(), skey.as_str().into()],
            )?;
            let cur = rows.first();
            let live = cur.is_some_and(|c| !c[4].flag());
            let version = cur.map_or(0, |c| c[2].i());
            if op == "insert" && live {
                let mut r = self.record(app, coll, cur.unwrap(), &cs)?;
                r["created"] = json!(false);
                return Ok((Some(r), 0, 0));
            }
            let value: Option<Value> = if op == "delete" {
                if !live {
                    return Ok((Some(json!({"deleted": false})), 0, 0));
                }
                None
            } else if op == "patch" {
                let Some(fields) = a.get("fields").and_then(Value::as_object) else { return Err("fields must be an object".into()) };
                let base = if live { self.open(app, coll, &skey, &cur.unwrap()[3].b().unwrap_or_default())?["v"].clone() } else { json!({}) };
                let Some(b) = base.as_object() else { return Err("patch needs an object value".into()) };
                let mut m: Map<String, Value> = b.clone();
                for (k, v) in fields {
                    m.insert(k.clone(), v.clone());
                }
                Some(Value::Object(m))
            } else {
                if let Some(iv) = a.get("if_version").filter(|v| !v.is_null()) {
                    let want = iv.as_i64().or_else(|| iv.as_str().and_then(|x| x.parse().ok())).unwrap_or(-1);
                    let have = if live { version } else { 0 };
                    if want != have {
                        return Err(format!("version conflict: have {have}"));
                    }
                }
                a.get("value").filter(|v| !v.is_null()).cloned()
            };
            let sealed = match &value {
                Some(v) => {
                    validate(v, cs.get("value").unwrap_or(&Value::Null), "value")?;
                    let sl = self.seal(app, coll, &skey, &key, v)?;
                    if sl.len() > MAX_VALUE {
                        return Err("value too large".into());
                    }
                    Some(sl)
                }
                None => None,
            };
            let seq = t.nextseq()?;
            let nv = version + 1;
            self.upsert(t, app, coll, &skey, seq, nv, sealed, sender, &self.now(), &self.node_id)?;
            self.audit(t, app, coll, &skey, op, sender, seq)?;
            let r = if op == "delete" {
                json!({"deleted": true, "seq": seq})
            } else {
                json!({"key": key, "value": value, "seq": seq, "version": nv, "created": op == "insert" || !live})
            };
            Ok((Some(r), seq, nv))
        })?;
        if seq != 0 {
            self.event(app, coll, &skey, &cs, seq, nv, op);
        }
        Ok(res.unwrap_or(Value::Null))
    }
    pub fn put(&self, a: &Value, c: Option<&str>, s: &str) -> R<Value> {
        self.write(a, c, s, "put")
    }
    pub fn insert(&self, a: &Value, c: Option<&str>, s: &str) -> R<Value> {
        self.write(a, c, s, "insert")
    }
    pub fn patch(&self, a: &Value, c: Option<&str>, s: &str) -> R<Value> {
        self.write(a, c, s, "patch")
    }
    pub fn delete(&self, a: &Value, c: Option<&str>, s: &str) -> R<Value> {
        self.write(a, c, s, "delete")
    }

    pub fn list(&self, a: &Value, cap: Option<&str>, sender: &str, include_deleted: Option<bool>) -> R<Value> {
        let (app, coll) = (s(a, "app"), s(a, "coll"));
        let scope = self.gate(app, coll, "read", cap, sender)?;
        let (app, coll) = (app.unwrap(), coll.unwrap_or(""));
        let cs = self.coll_schema(app, coll)?;
        let mut prefix = s(a, "prefix").unwrap_or("").to_string();
        if scope == "own" {
            if cs.get("per_person").and_then(Value::as_bool) != Some(true) {
                return Err("collection is not per_person".into());
            }
            prefix = format!("{sender}/{prefix}");
        }
        let hk = cs.get("hash_keys").is_some_and(|v| v != &Value::Bool(false) && !v.is_null());
        if !prefix.is_empty() && hk {
            return Err("prefix scan is impossible on a hash_keys collection".into());
        }
        let since = a.get("since").and_then(Value::as_i64).unwrap_or(0);
        let limit = a.get("limit").and_then(Value::as_i64).filter(|l| *l != 0).unwrap_or(200).clamp(1, MAX_LIMIT);
        let dele = include_deleted.unwrap_or_else(|| a.get("include_deleted").and_then(Value::as_bool).unwrap_or(false));
        let like = format!("{}%", prefix.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
        let mut sql = "SELECT key,seq,version,value,deleted FROM records WHERE app=? AND coll=? AND seq>? AND key LIKE ? ESCAPE '\\'".to_string();
        let mut p: Vec<V> = vec![app.into(), coll.into(), since.into(), like.into()];
        if !dele {
            sql.push_str(" AND deleted=?");
            p.push(V::Bool(false));
        }
        sql.push_str(" ORDER BY seq LIMIT ?");
        p.push(limit.into());
        let rows = self.db.q(&sql, &p)?;
        let items: Vec<Value> = rows.iter().map(|r| self.record(app, coll, r, &cs)).collect::<R<_>>()?;
        let next = if items.len() as i64 == limit { items.last().map(|i| i["seq"].clone()) } else { None };
        Ok(json!({"items": items, "next": next}))
    }
    pub fn changes(&self, a: &Value, cap: Option<&str>, sender: &str) -> R<Value> {
        self.list(a, cap, sender, Some(true))
    }

    pub fn get_schema(&self, a: &Value, cap: Option<&str>, sender: &str) -> R<Value> {
        let app = s(a, "app").unwrap_or("");
        let sc = self.schema(app)?.unwrap_or(json!({}));
        let colls: Vec<String> = sc.get("collections").and_then(Value::as_object).map(|o| o.keys().cloned().collect()).unwrap_or_default();
        if self.can(app, None, "admin", cap, sender) || colls.iter().any(|c| self.can(app, Some(c), "read", cap, sender)) {
            return Ok(if sc.as_object().is_some_and(|o| o.is_empty()) { Value::Null } else { sc });
        }
        Err(format!("not authorized: {}", action(app, None, "admin")))
    }

    pub fn put_schema(&self, a: &Value, cap: Option<&str>, sender: &str) -> R<Value> {
        let app = s(a, "app");
        self.gate(app, None, "admin", cap, sender)?;
        let app = app.unwrap();
        let doc = a.get("schema").cloned().unwrap_or(Value::Null);
        let Some(colls) = doc.get("collections").and_then(Value::as_object).filter(|_| doc.get("app").and_then(Value::as_str) == Some(app)) else {
            return Err("schema must be {app, collections:{...}} with app matching".into());
        };
        for cn in colls.keys() {
            if !name_ok(cn) {
                return Err(format!("bad collection name '{cn}'"));
            }
        }
        if let Some(r) = doc.get("replicas") {
            if !r.as_array().is_some_and(|a| a.iter().all(|n| n.as_str().is_some_and(|n| !n.is_empty()))) {
                return Err("replicas must be a list of node ids or names".into());
            }
        }
        self.db.tx(|t| {
            self.put_schema_row(t, app, &doc, sender, &self.now())?;
            let seq = t.nextseq()?;
            self.audit(t, app, "_schema", app, "schema.put", sender, seq)
        })?;
        Ok(json!({"ok": true}))
    }

    fn put_schema_row(&self, t: &mut Tx, app: &str, doc: &Value, by: &str, hlc: &str) -> R<()> {
        self.schemas.lock().unwrap().clear();
        t.q(
            "INSERT INTO schemas(app,doc,updated_at,updated_by,hlc) VALUES (?,?,{TS},?,?) ON CONFLICT (app) DO UPDATE SET \
             doc=EXCLUDED.doc, updated_at=EXCLUDED.updated_at, updated_by=EXCLUDED.updated_by, hlc=EXCLUDED.hlc",
            &[app.into(), V::J(doc.clone()), by.into(), hlc.into()],
        )?;
        Ok(())
    }

    pub fn health(&self) -> R<Value> {
        let n = self.db.q("SELECT count(*), count(DISTINCT app) FROM records WHERE deleted=?", &[V::Bool(false)])?;
        let au = self.db.q("SELECT count(*) FROM audit", &[])?[0][0].i();
        let head = self.db.q("SELECT coalesce(max(seq),0) FROM records", &[])?[0][0].i();
        let peers: Map<String, Value> = self.db.q("SELECT peer, seq FROM repl_cursor", &[])?.iter().map(|r| (r[0].s(), json!(r[1].i()))).collect();
        Ok(json!({"backend": self.db.kind, "key_loaded": !self.master.is_empty(), "records": n[0][0].i(), "apps": n[0][1].i(),
                  "audit_rows": au, "head_seq": head, "node": self.node_id, "pulled_from": peers}))
    }

    /// Number of audit rows whose link or hash does not check (the chain resumes from each row's own hash, so one
    /// fork counts once). 0 = intact.
    pub fn verify_audit(&self) -> R<usize> {
        let (mut prev, mut bad) = ("0".repeat(64), 0);
        for r in self.db.q("SELECT prev_hash,app,coll,key,op,principal,seq,hash FROM audit ORDER BY id", &[])? {
            let want = sha_hex(&py_audit_json(&[&prev, &r[1].s(), &r[2].s(), &r[3].s(), &r[4].s(), &r[5].s()], r[6].i()));
            if r[0].s() != prev || r[7].s() != want {
                bad += 1;
            }
            prev = r[7].s();
        }
        Ok(bad)
    }

    /// Decrypt every live row (proves the key and the AES-GCM/AAD format match whoever wrote them). Returns (ok, bad).
    pub fn verify_rows(&self) -> R<(i64, i64)> {
        let (mut ok, mut bad) = (0, 0);
        for r in self.db.q("SELECT app,coll,key,value FROM records WHERE deleted=? AND value IS NOT NULL", &[V::Bool(false)])? {
            match r[3].b().map(|v| self.open(&r[0].s(), &r[1].s(), &r[2].s(), &v)) {
                Some(Ok(_)) => ok += 1,
                _ => bad += 1,
            }
        }
        Ok((ok, bad))
    }

    // ---- replication: every replica pulls from every other, last writer wins on (hlc, origin) ----
    fn replica_gate(&self, cap: Option<&str>, sender: &str) -> R<()> {
        if sender.is_empty() || !self.auth.ok(cap, REPLICA_ACTION, sender) {
            return Err(format!("not authorized: {REPLICA_ACTION}"));
        }
        Ok(())
    }

    pub fn repl_pull(&self, a: &Value, cap: Option<&str>, sender: &str) -> R<Value> {
        self.replica_gate(cap, sender)?;
        let sch = a.get("schemas").cloned().unwrap_or(Value::Bool(true));
        self.repl_rows(a.get("since").and_then(Value::as_i64).unwrap_or(0), a.get("limit").and_then(Value::as_i64), a.get("max_bytes").and_then(Value::as_i64), Some(sender), &sch, Some(sender))
    }

    pub fn schema_hlcs(&self) -> R<Value> {
        Ok(Value::Object(self.db.q("SELECT app, hlc FROM schemas", &[])?.iter().map(|r| (r[0].s(), json!(r[1].s()))).collect()))
    }

    /// `schemas`: true = all, false/null = none, object = the asker's schema_hlcs() (send only what it lacks).
    /// `to`: the receiving node; rows of an app whose schema `replicas` leaves it out are not sent (`last` still moves
    /// past them). `None` = unknown receiver: such rows are never sent.
    #[allow(clippy::too_many_arguments)]
    pub fn repl_rows(&self, since: i64, limit: Option<i64>, max_bytes: Option<i64>, skip_origin: Option<&str>, schemas: &Value, to: Option<&str>) -> R<Value> {
        let limit = limit.filter(|l| *l != 0).unwrap_or(500).clamp(1, MAX_LIMIT);
        let budget = max_bytes.filter(|b| *b != 0).unwrap_or(REPL_BYTES as i64).clamp(512, (MAX_VALUE * 2) as i64) as usize;
        let rows = self.db.q(
            "SELECT app,coll,key,seq,version,value,deleted,hlc,origin,updated_by FROM records WHERE seq>? ORDER BY seq LIMIT ?",
            &[since.into(), limit.into()],
        )?;
        let (mut out, mut size, mut last, mut cut) = (vec![], 0usize, since, false);
        for r in &rows {
            let val = r[5].b();
            let vl = val.as_ref().map_or(0, Vec::len);
            if !out.is_empty() && size + vl * 4 / 3 > budget {
                cut = true;
                break;
            }
            last = r[3].i();
            if Some(r[8].s().as_str()) == skip_origin {
                continue;
            }
            if !self.replica_ok(&r[0].s(), to)? {
                continue; // residency: this app's rows stay on its named replicas
            }
            size += vl * 4 / 3 + 200;
            out.push(json!({"app": r[0].s(), "coll": r[1].s(), "key": r[2].s(), "seq": r[3].i(), "version": r[4].i(), "deleted": r[6].flag(),
                "value": val.map(|v| base64::engine::general_purpose::STANDARD.encode(v)), "hlc": r[7].s(), "origin": r[8].s(), "by": r[9].s()}));
        }
        let docs: Vec<Value> = if matches!(schemas, Value::Bool(false) | Value::Null) {
            vec![]
        } else {
            self.db
                .q("SELECT app,doc,hlc,updated_by FROM schemas", &[])?
                .iter()
                .filter(|r| match schemas.as_object() {
                    Some(m) => m.get(&r[0].s()).and_then(Value::as_str).is_none_or(|h| r[2].s().as_str() > h),
                    None => true,
                })
                .map(|r| json!({"app": r[0].s(), "doc": r[1].json(), "hlc": r[2].s(), "by": r[3].s()}))
                .collect()
        };
        Ok(json!({"rows": out, "last": last, "more": cut || rows.len() as i64 == limit, "schemas": docs}))
    }

    pub fn repl_since(&self, _a: &Value, cap: Option<&str>, sender: &str) -> R<Value> {
        self.replica_gate(cap, sender)?;
        Ok(json!({"since": self.cursor(sender)?, "schemas": self.schema_hlcs()?}))
    }

    pub fn repl_push(&self, a: &Value, cap: Option<&str>, sender: &str) -> R<Value> {
        self.replica_gate(cap, sender)?;
        let cur = self.cursor(sender)?;
        if a.get("since").and_then(Value::as_i64).unwrap_or(0) != cur {
            return Ok(json!({"applied": 0, "since": cur, "stale": true}));
        }
        let n = self.repl_apply(sender, a.get("reply").unwrap_or(&Value::Null))?;
        Ok(json!({"applied": n, "since": self.cursor(sender)?}))
    }

    /// Fold a peer's pull reply in. Returns how many rows changed here.
    pub fn repl_apply(&self, peer: &str, reply: &Value) -> R<i64> {
        let mut changed = 0;
        for sc in reply.get("schemas").and_then(Value::as_array).into_iter().flatten() {
            let app = sc["app"].as_str().unwrap_or("");
            let mine = self.db.q("SELECT hlc FROM schemas WHERE app=?", &[app.into()])?;
            let h = sc.get("hlc").and_then(Value::as_str).unwrap_or("");
            if mine.is_empty() || h > mine[0][0].s().as_str() {
                self.db.tx(|t| self.put_schema_row(t, app, &sc["doc"], sc.get("by").and_then(Value::as_str).unwrap_or(peer), h))?;
            }
        }
        for r in reply.get("rows").and_then(Value::as_array).into_iter().flatten() {
            let (app, coll, key) = (r["app"].as_str().unwrap_or(""), r["coll"].as_str().unwrap_or(""), r["key"].as_str().unwrap_or(""));
            if !self.replica_ok(app, Some(&self.node_id))? {
                continue; // a sender without the residency filter: never store it here
            }
            let (hlc, origin) = (r["hlc"].as_str().unwrap_or(""), r["origin"].as_str().unwrap_or(""));
            self.observe(hlc);
            let applied = self.db.tx(|t| {
                let cur = t.q("SELECT hlc, origin, version FROM records WHERE app=? AND coll=? AND key=? FOR UPDATE", &[app.into(), coll.into(), key.into()])?;
                if let Some(c) = cur.first() {
                    if (c[0].s().as_str(), c[1].s().as_str()) >= (hlc, origin) {
                        return Ok(None);
                    }
                }
                let seq = t.nextseq()?;
                let ver = cur.first().map_or(0, |c| c[2].i()).max(r["version"].as_i64().unwrap_or(0)) + i64::from(!cur.is_empty());
                let val = match r.get("value").and_then(Value::as_str) {
                    Some(b) => Some(base64::engine::general_purpose::STANDARD.decode(b).map_err(|e| e.to_string())?),
                    None => None,
                };
                self.upsert(t, app, coll, key, seq, ver, val, r.get("by").and_then(Value::as_str).unwrap_or(peer), hlc, origin)?;
                self.audit(t, app, coll, key, "repl", peer, seq)?;
                Ok(Some((seq, ver)))
            })?;
            let Some((seq, ver)) = applied else { continue };
            changed += 1;
            let cs = self.schema(app)?.and_then(|s| s.get("collections")?.get(coll).cloned()).unwrap_or(json!({}));
            self.event(app, coll, key, &cs, seq, ver, "repl");
        }
        self.db.tx(|t| {
            t.q("INSERT INTO repl_cursor(peer, seq) VALUES (?,?) ON CONFLICT (peer) DO UPDATE SET seq=EXCLUDED.seq", &[peer.into(), reply.get("last").and_then(Value::as_i64).unwrap_or(0).into()])?;
            Ok(())
        })?;
        Ok(changed)
    }

    pub fn cursor(&self, peer: &str) -> R<i64> {
        Ok(self.db.q("SELECT seq FROM repl_cursor WHERE peer=?", &[peer.into()])?.first().map_or(0, |r| r[0].i()))
    }
}

#[cfg(test)]
mod residency_tests {
    //! A schema's `replicas` list keeps an app's rows on the nodes it names (EU residency for twin-access): the sender
    //! leaves them out, the receiver refuses them, a local write on another node is refused, the schema still travels.
    use super::*;
    use ce_gate::ce_identity::Identity;

    const EU: &str = "twin-access";
    const OPEN: &str = "work-show";

    struct N {
        st: Store,
        id: String,
        cap: String,
    }

    fn node(dir: &std::path::Path, seed: u8) -> N {
        let me = Identity::from_secret_bytes(&[seed; 32]);
        let acts = [action(EU, None, "admin"), action(EU, Some("members"), "write"), action(EU, Some("members"), "read"), action(OPEN, None, "admin"), action(OPEN, Some("rooms"), "write")];
        let cap = ce_gate::ce_cap::encode_chain(&ce_gate::self_chain(&me, acts.to_vec(), 600));
        let db = Db::open(&format!("sqlite:{}/{seed}.db", dir.display())).unwrap();
        let st = Store::new(db, vec![7u8; 32], Auth::new(me.node_id()), me.node_id_hex(), Box::new(|_| {})).unwrap();
        N { st, id: me.node_id_hex(), cap }
    }

    /// node-a, node-b, node-c (ssh alias node-c-ssh), each knowing every name; node-a holds both schemas.
    fn cluster(replicas: Value) -> (std::path::PathBuf, N, N, N) {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!("ss-residency-{}-{}", std::process::id(), NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        let (mut d, mut l, mut m) = (node(&dir, 1), node(&dir, 2), node(&dir, 3));
        let names: HashMap<String, Vec<String>> =
            [(d.id.clone(), vec!["node-a".into()]), (l.id.clone(), vec!["node-b".into()]), (m.id.clone(), vec!["node-c".into(), "node-c-ssh".into()])].into();
        for n in [&mut d, &mut l, &mut m] {
            n.st.names = names.clone();
        }
        put_schema(&d, EU, "members", Some(replicas));
        put_schema(&d, OPEN, "rooms", None);
        (dir, d, l, m)
    }

    fn put_schema(n: &N, app: &str, coll: &str, replicas: Option<Value>) {
        let mut doc = json!({"app": app, "collections": {coll: {"value": {"type": "object"}}}});
        if let Some(r) = replicas {
            doc["replicas"] = r;
        }
        n.st.put_schema(&json!({"app": app, "schema": doc}), Some(&n.cap), &n.id).unwrap();
    }

    fn put(n: &N, app: &str, coll: &str, key: &str) -> R<Value> {
        n.st.put(&json!({"app": app, "coll": coll, "key": key, "value": {"k": key}}), Some(&n.cap), &n.id)
    }

    fn count(n: &N, app: &str) -> i64 {
        n.st.db.q("SELECT count(*) FROM records WHERE app=?", &[app.into()]).unwrap()[0][0].i()
    }

    fn apps(page: &Value) -> Vec<String> {
        page["rows"].as_array().unwrap().iter().map(|r| r["app"].as_str().unwrap().to_string()).collect()
    }

    fn head(n: &N) -> i64 {
        n.st.db.q("SELECT max(seq) FROM records", &[]).unwrap()[0][0].i()
    }

    #[test]
    fn sender_leaves_eu_rows_out_and_last_moves_past_them() {
        let (dir, d, l, m) = cluster(json!(["node-a", "node-b"]));
        put(&d, EU, "members", "t1|anna").unwrap();
        put(&d, OPEN, "rooms", "r1").unwrap();
        // node-c pulls (skip_origin = to = the asker, as repl_pull and the mesh push pass it)
        let page = d.st.repl_rows(0, None, None, Some(&m.id), &json!(true), Some(&m.id)).unwrap();
        assert_eq!(apps(&page), vec![OPEN]);
        assert_eq!(page["last"].as_i64(), Some(head(&d)));
        assert!(page["schemas"].as_array().unwrap().iter().any(|s| s["app"] == EU), "the schema still travels");
        m.st.repl_apply(&d.id, &page).unwrap();
        assert_eq!((count(&m, EU), count(&m, OPEN)), (0, 1));
        assert_eq!(m.st.schema(EU).unwrap().unwrap()["replicas"], json!(["node-a", "node-b"]));
        assert_eq!(m.st.cursor(&d.id).unwrap(), head(&d));
        // node-b is named: it gets them
        let page = d.st.repl_rows(0, None, None, Some(&l.id), &json!(true), Some(&l.id)).unwrap();
        assert_eq!(apps(&page), vec![EU, OPEN]);
        l.st.repl_apply(&d.id, &page).unwrap();
        assert_eq!(count(&l, EU), 1);
        // an unknown receiver (a name that is in no node-names line, or none) never gets them
        assert_eq!(apps(&d.st.repl_rows(0, None, None, None, &json!(false), None).unwrap()), vec![OPEN]);
        assert_eq!(apps(&d.st.repl_rows(0, None, None, None, &json!(false), Some("node-x")).unwrap()), vec![OPEN]);
        assert_eq!(apps(&d.st.repl_rows(0, None, None, None, &json!(false), Some("node-b")).unwrap()), vec![EU, OPEN]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn receiver_drops_rows_an_old_sender_sent() {
        let (dir, d, l, m) = cluster(json!(["node-a", "node-b"]));
        m.st.repl_apply(&d.id, &d.st.repl_rows(0, None, None, None, &json!(true), Some(&m.id)).unwrap()).unwrap();
        put(&d, EU, "members", "t1|anna").unwrap();
        put(&d, OPEN, "rooms", "after").unwrap();
        let page = d.st.repl_rows(m.st.cursor(&d.id).unwrap(), None, None, None, &json!(false), Some(&l.id)).unwrap(); // unfiltered for m
        assert_eq!(apps(&page), vec![EU, OPEN]);
        assert_eq!(m.st.repl_apply(&d.id, &page).unwrap(), 1);
        assert_eq!((count(&m, EU), count(&m, OPEN)), (0, 1));
        assert_eq!(m.st.cursor(&d.id).unwrap(), page["last"].as_i64().unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn local_write_on_an_unlisted_node_is_refused() {
        let (dir, d, _l, m) = cluster(json!(["node-a", "node-b"]));
        m.st.repl_apply(&d.id, &d.st.repl_rows(0, None, None, None, &json!(true), Some(&m.id)).unwrap()).unwrap();
        let e = put(&m, EU, "members", "t1|x").unwrap_err();
        assert!(e.contains("keeps its rows only on replicas") && e.contains("node-a"), "{e}");
        assert_eq!(count(&m, EU), 0);
        put(&m, OPEN, "rooms", "fine").unwrap();
        put(&d, EU, "members", "t1|y").unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_list_of_node_ids_works_without_names() {
        let (dir, mut d, l, mut m) = cluster(json!([]));
        put_schema(&d, EU, "members", Some(json!([d.id.clone(), m.id.clone()])));
        d.st.names.clear();
        m.st.names.clear();
        put(&d, EU, "members", "k").unwrap();
        assert_eq!(apps(&d.st.repl_rows(0, None, None, None, &json!(false), Some(&l.id)).unwrap()), Vec::<String>::new());
        assert_eq!(apps(&d.st.repl_rows(0, None, None, None, &json!(false), Some(&m.id)).unwrap()), vec![EU]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn change_event_of_a_residency_app_has_no_key() {
        let dir = std::env::temp_dir().join(format!("ss-residency-ev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let me = Identity::from_secret_bytes(&[9; 32]);
        let acts = vec![action(EU, None, "admin"), action(EU, Some("members"), "write"), action(OPEN, None, "admin"), action(OPEN, Some("rooms"), "write")];
        let cap = ce_gate::ce_cap::encode_chain(&ce_gate::self_chain(&me, acts, 600));
        let evs: std::sync::Arc<Mutex<Vec<Value>>> = Default::default();
        let e2 = evs.clone();
        let st = Store::new(Db::open(&format!("sqlite:{}/ev.db", dir.display())).unwrap(), vec![7u8; 32], Auth::new(me.node_id()), me.node_id_hex(), Box::new(move |ev| e2.lock().unwrap().push(ev))).unwrap();
        let n = N { st, id: me.node_id_hex(), cap };
        put_schema(&n, EU, "members", Some(json!([n.id.clone()])));
        put_schema(&n, OPEN, "rooms", None);
        put(&n, EU, "members", "t1|anna").unwrap();
        put(&n, OPEN, "rooms", "r").unwrap();
        let evs = evs.lock().unwrap();
        assert!(evs[0].get("key").is_none() && evs[0].get("key_hash").is_none() && evs[0]["app"] == EU);
        assert_eq!(evs[1]["key"], "r");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bad_replicas_list_is_refused() {
        let (dir, d, _l, _m) = cluster(json!(["node-a"]));
        for bad in [json!("node-a"), json!([""]), json!([1])] {
            let e = d.st.put_schema(&json!({"app": EU, "schema": {"app": EU, "replicas": bad, "collections": {}}}), Some(&d.cap), &d.id).unwrap_err();
            assert!(e.contains("replicas must be a list"), "{e}");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn node_names_file_parses_like_python() {
        let dir = std::env::temp_dir().join(format!("ss-names-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (p, own) = (dir.join("names"), dir.join("own"));
        std::fs::write(&p, "# id name aliases\nmmm node-c node-c-ssh  # laptop\n\nlll node-b\nlonely\n").unwrap();
        std::fs::write(&own, "node-a\n").unwrap();
        let n = load_node_names(&p, "ddd", &own);
        assert_eq!(n.len(), 3);
        assert_eq!(n["mmm"], vec!["node-c", "node-c-ssh"]);
        assert_eq!(n["lll"], vec!["node-b"]);
        assert_eq!(n["ddd"], vec!["node-a"]);
        assert!(load_node_names(&dir.join("missing"), "", &own).is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
