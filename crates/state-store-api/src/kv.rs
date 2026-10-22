//! A cell's own rows, behind one trait: [`Kv`]. [`StoreKv`] is state.store through the typed blocking client (one
//! app per cell, a collection per table, a key per record); [`MemKv`] keeps the same rows in memory for unit tests
//! and `--state mem` dev runs; [`fake::serve`] is an in-process state.store (same typed API, same version and
//! compare-and-set rules, empty cap refused) so a test drives the real `StoreKv` over a real ce-wire connection.
//!
//! Every value is JSON text of at most [`MAX_VALUE`] bytes; `put` checks it before the call. `expect` is the
//! compare-and-set of state.store: `Some(v)` writes only over version `v`, `Some(0)` only when the key is absent,
//! `None` overwrites.
use crate::*;
use ce_wire::blocking::Client;
use ce_wire::Api;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// One live row: key, value (JSON text), version.
pub type Row = (String, String, u64);

pub trait Kv: Send + Sync {
    fn get(&self, coll: &str, key: &str) -> Result<Option<(String, u64)>, String>;
    /// Write and return the new version. A version conflict is an `Err` containing "version".
    fn put(&self, coll: &str, key: &str, value: &str, expect: Option<u64>) -> Result<u64, String>;
    fn del(&self, coll: &str, key: &str) -> Result<(), String>;
    /// Every live row under `prefix`, all pages.
    fn list(&self, coll: &str, prefix: &str) -> Result<Vec<Row>, String>;
    /// "mem" or "state.store", for health ops.
    fn backend(&self) -> &'static str;
}

/// Read-modify-write with compare-and-set, retried on a version conflict (at most 8 tries). `f` gets the current
/// value (None if absent) and returns the new one, or None to leave the row alone. Returns the value written.
pub fn update(kv: &dyn Kv, coll: &str, key: &str, f: &mut dyn FnMut(Option<&str>) -> Result<Option<String>, String>) -> Result<Option<String>, String> {
    for _ in 0..8 {
        let cur = kv.get(coll, key)?;
        let Some(next) = f(cur.as_ref().map(|(v, _)| v.as_str()))? else { return Ok(None) };
        match kv.put(coll, key, &next, Some(cur.as_ref().map(|(_, v)| *v).unwrap_or(0))) {
            Ok(_) => return Ok(Some(next)),
            Err(e) if e.contains("version") => continue,
            Err(e) => return Err(e),
        }
    }
    Err(format!("{coll}/{key}: compare-and-set lost 8 times in a row"))
}

#[derive(Default)]
pub struct MemKv(Mutex<BTreeMap<(String, String), (String, u64)>>);

impl MemKv {
    pub fn new() -> Arc<MemKv> {
        Arc::new(MemKv::default())
    }
}

fn cas(m: &mut BTreeMap<(String, String), (String, u64)>, coll: &str, key: &str, value: &str, expect: Option<u64>) -> Result<u64, String> {
    check_value(value)?;
    let k = (coll.to_string(), key.to_string());
    let have = m.get(&k).map(|(_, v)| *v).unwrap_or(0);
    if let Some(e) = expect {
        if e != have {
            return Err(format!("version conflict on {coll}/{key}: expected {e}, have {have}"));
        }
    }
    m.insert(k, (value.into(), have + 1));
    Ok(have + 1)
}

impl Kv for MemKv {
    fn get(&self, coll: &str, key: &str) -> Result<Option<(String, u64)>, String> {
        Ok(self.0.lock().unwrap().get(&(coll.into(), key.into())).cloned())
    }
    fn put(&self, coll: &str, key: &str, value: &str, expect: Option<u64>) -> Result<u64, String> {
        cas(&mut self.0.lock().unwrap(), coll, key, value, expect)
    }
    fn del(&self, coll: &str, key: &str) -> Result<(), String> {
        self.0.lock().unwrap().remove(&(coll.into(), key.into()));
        Ok(())
    }
    fn list(&self, coll: &str, prefix: &str) -> Result<Vec<Row>, String> {
        Ok(self.0.lock().unwrap().iter().filter(|((c, k), _)| c == coll && k.starts_with(prefix)).map(|((_, k), (v, n))| (k.clone(), v.clone(), *n)).collect())
    }
    fn backend(&self) -> &'static str {
        "mem"
    }
}

/// How a [`StoreKv`] reaches state.store: `by_name` through the door (production), or one address (the fake).
pub enum Reach {
    ByName,
    At(std::net::SocketAddr),
}

/// state.store for one app. `cap` is the hex grant of `state.<app>.*` (`state-grant self <app> <coll> --read --write
/// --wallet`, then `ce-iam wallet show state.store:<app>@<node16>`); `token` makes a fresh Hello proof (normally
/// `ce_gate::self_proof::<StateStore>(600)`). One connection behind a lock; a failed call drops it, and a read is
/// retried once on a fresh one. A write is never retried here (a timed-out write may have landed).
pub struct StoreKv {
    app: String,
    cap: String,
    token: Box<dyn Fn() -> Result<Vec<u8>, String> + Send + Sync>,
    reach: Reach,
    /// the open connection and the cap that replica honours
    conn: Mutex<Option<(Client<StateStore>, String)>>,
    /// when `conn` last answered: a write never goes down a connection idle longer than [`WRITE_FRESH`]
    used: Mutex<std::time::Instant>,
    others: Others,
}

/// A connection idle this long is replaced before a write. A write is never resent after a closed connection (it may
/// have landed), so a connection the replica dropped while idle (its restart, an idle timeout) failed the next write
/// outright (a chat cell answered a message with Failed("state.store: Closed") hours after the replica had
/// restarted). A read still reconnects and retries on its own.
pub const WRITE_FRESH: std::time::Duration = std::time::Duration::from_secs(20);
#[cfg(not(test))]
fn write_fresh() -> std::time::Duration {
    WRITE_FRESH
}
#[cfg(test)]
fn write_fresh() -> std::time::Duration {
    std::time::Duration::from_millis(200)
}

/// How long one state.store call waits for its answer. ce-wire's default is 1 s, and a replica on a loaded host
/// (load 40) answers later than that, so other cells got `Timeout` on every read.
pub const CALL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// The exact start of a state.store error where the database was not reached and nothing was written
/// (`state_store::db::UNAVAILABLE`): the same call, read or write, may go to another replica.
pub const UNAVAILABLE: &str = "store unavailable: ";

/// Other replicas to try when one answers [`UNAVAILABLE`]: `(addr, cap)`, nearest first, each with the cap that
/// replica honours (every replica trusts only grants rooted at its own key).
pub type Others = Box<dyn Fn(&str) -> Vec<(String, String, Option<String>)> + Send + Sync>;

/// The grant for `app` on the replica whose node id starts with `node16`, from the ce-iam wallet:
/// `state.store:<app>@<node16>`, then `state.store@<node16>` (the Python client's find_cap, per replica).
pub fn wallet_cap(app: &str, node16: &str) -> Option<String> {
    [format!("state.store:{app}@{node16}"), format!("state.store@{node16}")].iter().find_map(|l| wallet_show(l))
}

/// The token of wallet entry `label` from `ce-iam wallet show` (at most 10 s). Runs ce-iam itself and kills it at
/// 10 s: macOS has no `timeout(1)`, and `timeout 10 ce-iam ...` there failed to spawn, so every wallet lookup on
/// macOS came back None and the client fell back to a self proof the replica refuses.
fn wallet_show(label: &str) -> Option<String> {
    let mut child = std::process::Command::new("ce-iam").args(["wallet", "show", label])
        .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn().ok()?;
    let t0 = std::time::Instant::now();
    let st = loop {
        match child.try_wait().ok()? {
            Some(st) => break st,
            None if t0.elapsed() > std::time::Duration::from_secs(10) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            None => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    };
    let mut out = String::new();
    std::io::Read::read_to_string(&mut child.stdout.take()?, &mut out).ok()?;
    st.success().then(|| out.lines().filter_map(|l| l.split_whitespace().last()).find(|t| t.len() > 64 && t.bytes().all(|b| b.is_ascii_hexdigit())).map(String::from)).flatten()
}

/// The configured state.store replicas as (`host:port`, node id prefix): `STATE_STORE_REPLICAS` (`;`-separated), else
/// `~/.config/ce-state/replicas`, one `host:port node16` per line (`#` comments). StoreKv's list when net.find has
/// no answer, so a cell still reaches another replica while net.find itself is down.
pub fn configured_replicas() -> Vec<(String, String)> {
    let text = std::env::var("STATE_STORE_REPLICAS").ok().filter(|v| !v.trim().is_empty()).map(|v| v.replace(';', "\n")).unwrap_or_else(|| {
        std::fs::read_to_string(format!("{}/.config/ce-state/replicas", std::env::var("HOME").unwrap_or_default())).unwrap_or_default()
    });
    parse_replicas(&text)
}

fn parse_replicas(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            let (addr, node) = (w.next()?, w.next()?);
            (addr.contains(':') && node.len() >= 16 && node.bytes().all(|b| b.is_ascii_hexdigit())).then(|| (addr.to_string(), node[..16].to_string()))
        })
        .collect()
}

/// The door grant for the replica whose node id starts with `node16`: wallet `state.store:hello@<node16>`, minted by that
/// replica's key with `state.store:read` + `state.store:write`. A replica's door trusts only chains rooted at its own key
/// (`state.store` is own-key-only), so this node's self proof is refused there; the per-app cap is still checked per call.
pub fn hello_cap(node16: &str) -> Option<String> {
    wallet_show(&format!("state.store:hello@{node16}"))
}

/// The Hello for another replica: this node's proof of that replica's door grant (see [`hello_cap`]), signed now.
fn replica_hello(cap: &str) -> Option<Vec<u8>> {
    let chain = ce_gate::chain_from_hex(cap.trim()).ok()?;
    Some(ce_gate::proof::<StateStore>(&ce_gate::node_identity().ok()?, &chain))
}

/// net.find's healthy state.store replicas of this schema, nearest first, then the [`configured_replicas`] net.find
/// did not name; each with its wallet cap, and one without a cap is left out (it would refuse).
pub fn found_replicas(app: &str) -> Vec<(String, String, Option<String>)> {
    // net.find refuses an empty token: give it this node's proof here, so no cell has to remember enable_find()
    static FIND: std::sync::Once = std::sync::Once::new();
    FIND.call_once(ce_gate::enable_find);
    let mut v: Vec<(String, String)> = match ce_wire::find::find_blocking(StateStore::NAME, StateStore::VERSION as u16) {
        Some(Ok(r)) => {
            let mut r: Vec<_> = r.replicas.into_iter().filter(|x| x.schema_hash == StateStore::SCHEMA).collect();
            r.sort_by_key(|x| x.healthy_ms);
            r.into_iter().map(|x| (x.addr, x.node.get(..16).unwrap_or(&x.node).to_string())).collect()
        }
        _ => vec![],
    };
    for c in configured_replicas() {
        if !v.iter().any(|x| x.0 == c.0) {
            v.push(c);
        }
    }
    v.into_iter().filter_map(|(addr, node16)| wallet_cap(app, &node16).map(|c| (addr, c, hello_cap(&node16)))).collect()
}

impl StoreKv {
    pub fn new(app: &str, cap: String, token: Box<dyn Fn() -> Result<Vec<u8>, String> + Send + Sync>, reach: Reach) -> Result<Arc<StoreKv>, String> {
        check_name("app", app)?;
        if cap.trim().is_empty() {
            return Err(format!("state.store: no cap for app {app} (state-grant self {app} <coll> --read --write --wallet)"));
        }
        let others: Others = match reach {
            Reach::ByName => Box::new(found_replicas),
            Reach::At(_) => Box::new(|_: &str| vec![]),
        };
        Self::with_others(app, cap, token, reach, others)
    }

    /// [`StoreKv::new`] with its own list of other replicas (tests; a cell that knows its replicas).
    pub fn with_others(app: &str, cap: String, token: Box<dyn Fn() -> Result<Vec<u8>, String> + Send + Sync>, reach: Reach, others: Others) -> Result<Arc<StoreKv>, String> {
        check_name("app", app)?;
        if cap.trim().is_empty() {
            return Err(format!("state.store: no cap for app {app} (state-grant self {app} <coll> --read --write --wallet)"));
        }
        Ok(Arc::new(StoreKv { app: app.into(), cap: cap.trim().into(), token, reach, conn: Mutex::new(None), used: Mutex::new(std::time::Instant::now()), others }))
    }

    /// One call. `f` gets the client and the cap that replica honours. A replica answering [`UNAVAILABLE`] (its
    /// database down, nothing written) hands the call, read or write, to the next of [`Others`]; that one stays the
    /// connection until it fails. A timeout or a closed connection is never resent for a write (it may have landed).
    fn with<T>(&self, retry: bool, f: &dyn Fn(&Client<StateStore>, &str) -> Result<T, ce_wire::WireError>) -> Result<T, String> {
        let mut g = self.conn.lock().unwrap();
        if !retry && g.is_some() && self.used.lock().unwrap().elapsed() > write_fresh() {
            *g = None;
        }
        for attempt in 0..2 {
            if g.is_none() {
                let t = (self.token)()?;
                let c = match self.reach {
                    Reach::ByName => Client::<StateStore>::by_name(t),
                    Reach::At(a) => Client::<StateStore>::connect(a, t),
                }
                .map_err(|e| format!("state.store unreachable: {e:?}"))?;
                c.set_deadline(CALL_DEADLINE);
                *g = Some((c, self.cap.clone()));
            }
            let (c, cap) = g.as_ref().unwrap();
            let r = f(c, cap);
            if r.is_ok() || matches!(r, Err(ce_wire::WireError::Refused(_))) {
                *self.used.lock().unwrap() = std::time::Instant::now();
            }
            match r {
                Ok(v) => return Ok(v),
                Err(ce_wire::WireError::Refused(ce_wire::Refusal::Remote(m))) if m.starts_with(UNAVAILABLE) => {
                    *g = None;
                    return self.next_replica(&mut g, f, m);
                }
                Err(ce_wire::WireError::Refused(r)) => return Err(format!("state.store refused: {r:?}")),
                Err(e) => {
                    *g = None;
                    if !(retry && attempt == 0) {
                        return Err(format!("state.store: {e:?}"));
                    }
                }
            }
        }
        Err("state.store: reconnect failed".into())
    }

    fn next_replica<T>(&self, g: &mut Option<(Client<StateStore>, String)>, f: &dyn Fn(&Client<StateStore>, &str) -> Result<T, ce_wire::WireError>, first: String) -> Result<T, String> {
        let mut why = vec![first];
        for (addr, cap, hello) in (self.others)(&self.app) {
            let c = match Client::<StateStore>::connect(addr.as_str(), hello.as_deref().and_then(replica_hello).map_or_else(|| (self.token)(), Ok)?) {
                Ok(c) => c,
                Err(e) => {
                    why.push(format!("{addr}: {e:?}"));
                    continue;
                }
            };
            c.set_deadline(CALL_DEADLINE);
            match f(&c, &cap) {
                Ok(v) => {
                    *g = Some((c, cap));
                    *self.used.lock().unwrap() = std::time::Instant::now();
                    return Ok(v);
                }
                Err(ce_wire::WireError::Refused(ce_wire::Refusal::Remote(m))) if m.starts_with(UNAVAILABLE) => why.push(format!("{addr}: {m}")),
                Err(ce_wire::WireError::Refused(r)) => return Err(format!("state.store refused at {addr}: {r:?}")),
                // a transport failure after the request went out: a write may have landed there, so stop
                Err(e) => return Err(format!("state.store at {addr}: {e:?}")),
            }
        }
        Err(format!("state.store: every replica unavailable: {}", why.join("; ")))
    }
    fn at(&self, coll: &str) -> Coll {
        Coll { app: self.app.clone(), coll: coll.into() }
    }
}

impl Kv for StoreKv {
    fn get(&self, coll: &str, key: &str) -> Result<Option<(String, u64)>, String> {
        Ok(self.with(true, &|c, cap| c.call::<Get>(&GetReq { at: self.at(coll), key: key.into(), cap: cap.into() }))?.filter(|d| !d.deleted).map(|d| (d.value, d.version)))
    }
    fn put(&self, coll: &str, key: &str, value: &str, expect: Option<u64>) -> Result<u64, String> {
        check_value(value)?;
        let put = |c: &Client<StateStore>, cap: &str| c.call::<Put>(&PutReq { at: self.at(coll), key: key.into(), value: value.into(), if_version: expect, insert_only: false, cap: cap.into() });
        Ok(self.with(false, &put)?.version)
    }
    fn del(&self, coll: &str, key: &str) -> Result<(), String> {
        self.with(false, &|c, cap| c.call::<Delete>(&DeleteReq { at: self.at(coll), key: key.into(), cap: cap.into() }))
    }
    fn list(&self, coll: &str, prefix: &str) -> Result<Vec<Row>, String> {
        let (mut out, mut since) = (Vec::new(), 0);
        for _ in 0..1000 {
            let p = self.with(true, &|c, cap| c.call::<List>(&ListReq { at: self.at(coll), prefix: prefix.into(), since, limit: MAX_PAGE, include_deleted: false, cap: cap.into() }))?;
            out.extend(p.docs.into_iter().filter(|d| !d.deleted).map(|d| (d.key, d.value, d.version)));
            match p.next {
                Some(n) if n > since => since = n,
                _ => return Ok(out),
            }
        }
        Err(format!("{coll}: more than 1000 pages"))
    }
    fn backend(&self) -> &'static str {
        "state.store"
    }
}

/// Write-through with optimistic locking for a cell that keeps its tables in memory: `load` a collection on start
/// (remembers each row's version), `touch` the rows a change made dirty, then `flush` writes exactly those rows with
/// compare-and-set on the version it last saw (`Some(0)` for a new row). A row another replica changed in between
/// fails the flush with a "version" error; the cell then reloads and the caller retries. So a counter (an auth key's
/// uses left) or an approval can never be applied twice by two replicas.
pub struct Tracked {
    pub kv: Arc<dyn Kv>,
    ver: BTreeMap<(String, String), u64>,
    dirty: std::collections::BTreeSet<(String, String)>,
}

impl Tracked {
    pub fn new(kv: Arc<dyn Kv>) -> Tracked {
        Tracked { kv, ver: BTreeMap::new(), dirty: Default::default() }
    }
    /// Every live row of `coll` as (key, value); versions remembered, dirty marks of `coll` dropped.
    pub fn load(&mut self, coll: &str) -> Result<Vec<(String, String)>, String> {
        let rows = self.kv.list(coll, "")?;
        self.ver.retain(|(c, _), _| c != coll);
        self.dirty.retain(|(c, _)| c != coll);
        Ok(rows.into_iter().map(|(k, v, n)| { self.ver.insert((coll.into(), k.clone()), n); (k, v) }).collect())
    }
    pub fn touch(&mut self, coll: &str, key: &str) {
        self.dirty.insert((coll.into(), key.into()));
    }
    pub fn is_dirty(&self) -> bool {
        !self.dirty.is_empty()
    }
    /// Write the dirty rows. `render(coll, key)` gives the row's JSON now, or None if it was removed. On an error the
    /// rows not yet written stay dirty; the caller reloads (memory may hold a change state.store refused).
    pub fn flush(&mut self, render: &dyn Fn(&str, &str) -> Option<String>) -> Result<(), String> {
        while let Some(ck) = self.dirty.iter().next().cloned() {
            let (c, k) = (&ck.0, &ck.1);
            match render(c, k) {
                Some(v) => {
                    let n = self.kv.put(c, k, &v, Some(self.ver.get(&ck).copied().unwrap_or(0))).map_err(|e| format!("{c}/{k}: {e}"))?;
                    self.ver.insert(ck.clone(), n);
                }
                None => {
                    self.kv.del(c, k)?;
                    self.ver.remove(&ck);
                }
            }
            self.dirty.remove(&ck);
        }
        Ok(())
    }
}

/// The backend a cell picked at start: `--state mem` or `CE_STATE=mem` keeps rows in memory (dev, tests; lost on
/// restart); otherwise state.store by name, app `app`, cap from `STATE_STORE_CAP` or the file
/// `~/.config/ce-state/<app>.cap` (what `ce-iam wallet show state.store:<app>@<node16>` prints).
pub fn from_env(app: &str, token: Box<dyn Fn() -> Result<Vec<u8>, String> + Send + Sync>) -> Result<Arc<dyn Kv>, String> {
    let args: Vec<String> = std::env::args().collect();
    let flag = args.iter().position(|a| a == "--state").and_then(|i| args.get(i + 1)).cloned();
    let pick = flag.or_else(|| std::env::var("CE_STATE").ok()).unwrap_or_else(|| "store".into());
    match pick.as_str() {
        "mem" => Ok(MemKv::new()),
        "store" | "state.store" => {
            let cap = match std::env::var("STATE_STORE_CAP") {
                Ok(c) => c,
                Err(_) => {
                    let f = format!("{}/.config/ce-state/{app}.cap", std::env::var("HOME").unwrap_or_default());
                    std::fs::read_to_string(&f).map_err(|e| format!("no state.store cap for {app}: set STATE_STORE_CAP or write {f} ({e})"))?
                }
            };
            Ok(StoreKv::new(app, cap, token, Reach::ByName)?)
        }
        o => Err(format!("--state {o}: mem or store")),
    }
}

/// An in-process state.store for tests: the same typed API (Get, Put, Delete, List; Patch and Watch answer an
/// error), the same version and compare-and-set rules, an empty cap refused. Not the engine: no Postgres, no
/// encryption, no audit, every caller holds both rights. Binds 127.0.0.1 only.
pub mod fake {
    use super::*;
    use ce_wire::{Caller, Hello};

    type Rows = Arc<Mutex<(u64, BTreeMap<(String, String, String), Doc>)>>;

    /// Start it on a free loopback port; it runs until the process ends.
    pub fn serve() -> std::net::SocketAddr {
        let rows: Rows = Arc::default();
        let gate = |_: &Hello| Ok(Caller { name: "fake".into(), rights: vec!["state.store:read".into(), "state.store:write".into()] });
        fn ck(cap: &str, at: &Coll) -> Result<(String, String), String> {
            if cap.is_empty() {
                return Err("refused: empty cap".into());
            }
            check_name("app", &at.app)?;
            check_name("coll", &at.coll)?;
            Ok((at.app.clone(), at.coll.clone()))
        }
        let (r1, r2, r3, r4) = (rows.clone(), rows.clone(), rows.clone(), rows.clone());
        let srv = ce_wire::blocking::Server::<StateStore>::new(gate)
            .on::<Get, _>(move |r: GetReq, _| {
                let (a, c) = ck(&r.cap, &r.at)?;
                Ok(r1.lock().unwrap().1.get(&(a, c, r.key)).filter(|d| !d.deleted).cloned())
            })
            .on::<Put, _>(move |r: PutReq, _| {
                let (a, c) = ck(&r.cap, &r.at)?;
                check_key(&r.key)?;
                check_value(&r.value)?;
                serde_json_free_check(&r.value)?;
                let mut g = r2.lock().unwrap();
                let k = (a, c, r.key.clone());
                let have = g.1.get(&k).filter(|d| !d.deleted).map(|d| d.version).unwrap_or(0);
                if let Some(e) = r.if_version {
                    if e != have {
                        return Err(format!("version conflict: expected {e}, have {have}"));
                    }
                }
                g.0 += 1;
                let d = Doc { key: r.key, value: r.value, seq: g.0, version: have + 1, deleted: false };
                g.1.insert(k, d.clone());
                Ok(d)
            })
            .on::<Delete, _>(move |r: DeleteReq, _| {
                let (a, c) = ck(&r.cap, &r.at)?;
                let mut g = r3.lock().unwrap();
                g.0 += 1;
                let seq = g.0;
                if let Some(d) = g.1.get_mut(&(a, c, r.key)) {
                    d.deleted = true;
                    d.seq = seq;
                }
                Ok(())
            })
            .on::<List, _>(move |r: ListReq, _| {
                let (a, c) = ck(&r.cap, &r.at)?;
                let g = r4.lock().unwrap();
                let mut docs: Vec<Doc> = g.1.iter().filter(|((x, y, k), d)| *x == a && *y == c && k.starts_with(&r.prefix) && d.seq > r.since && (r.include_deleted || !d.deleted)).map(|(_, d)| d.clone()).collect();
                docs.sort_by_key(|d| d.seq);
                let lim = r.limit.clamp(1, MAX_PAGE) as usize;
                let next = if docs.len() > lim { Some(docs[lim - 1].seq) } else { None };
                docs.truncate(lim);
                Ok(Page { docs, next })
            });
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fake state.store");
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || srv.serve(l));
        addr
    }

    /// The engine refuses a value that is not JSON; the fake checks the cheap part (non-empty, starts like JSON).
    fn serde_json_free_check(v: &str) -> Result<(), String> {
        match v.trim_start().bytes().next() {
            Some(b'{' | b'[' | b'"' | b't' | b'f' | b'n' | b'-' | b'0'..=b'9') => Ok(()),
            _ => Err("value is not JSON".into()),
        }
    }

    /// A replica whose database is down: every op answers [`UNAVAILABLE`] (nothing written), like state.store with
    /// Postgres stopped.
    pub fn serve_unavailable() -> std::net::SocketAddr {
        let gate = |_: &Hello| Ok(Caller { name: "fake".into(), rights: vec!["state.store:read".into(), "state.store:write".into()] });
        let down = || format!("{UNAVAILABLE}error connecting to server: Connection refused");
        let srv = ce_wire::blocking::Server::<StateStore>::new(gate)
            .on::<Get, _>(move |_: GetReq, _| Err(down()))
            .on::<Put, _>(move |_: PutReq, _| Err(down()))
            .on::<Delete, _>(move |_: DeleteReq, _| Err(down()))
            .on::<List, _>(move |_: ListReq, _| Err(down()));
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fake state.store");
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || srv.serve(l));
        addr
    }

    /// A [`StoreKv`] for `app` on a fresh fake.
    pub fn store(app: &str) -> Arc<StoreKv> {
        StoreKv::new(app, "00".into(), Box::new(|| Ok(Vec::new())), Reach::At(serve())).unwrap()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn configured_replicas_parse() {
        let v = parse_replicas("# node-b\n192.0.2.10:7700 aaaabbbbccccdddd0000  # comment\nbad\nhost:1 nothex0000000000000\n\nh:2 0123456789abcdef");
        assert_eq!(v, vec![("192.0.2.10:7700".into(), "aaaabbbbccccdddd".into()), ("h:2".into(), "0123456789abcdef".into())]);
    }

    use super::*;

    fn exercise(kv: &dyn Kv) {
        assert_eq!(kv.get("t", "a").unwrap(), None);
        assert_eq!(kv.put("t", "a", "{\"n\":1}", Some(0)).unwrap(), 1);
        assert!(kv.put("t", "a", "{\"n\":9}", Some(0)).unwrap_err().contains("version"));
        assert_eq!(kv.put("t", "a", "{\"n\":2}", Some(1)).unwrap(), 2);
        kv.put("t", "b", "1", None).unwrap();
        kv.put("u", "a", "1", None).unwrap();
        assert_eq!(kv.list("t", "").unwrap().len(), 2);
        kv.del("t", "b").unwrap();
        assert_eq!(kv.list("t", "").unwrap().len(), 1);
        let n = update(kv, "t", "c", &mut |v| Ok(Some((v.map(|s| s.parse::<u64>().unwrap()).unwrap_or(0) + 1).to_string()))).unwrap();
        assert_eq!(n.as_deref(), Some("1"));
        assert!(kv.put("t", "big", &"x".repeat(2001), None).unwrap_err().contains("2000"));
    }

    #[test]
    fn tracked_refuses_a_stale_write() {
        let kv: Arc<dyn Kv> = fake::store("kv-test2");
        let (mut a, mut b) = (Tracked::new(kv.clone()), Tracked::new(kv.clone()));
        a.load("t").unwrap();
        b.load("t").unwrap();
        a.touch("t", "x");
        a.flush(&|_, _| Some("1".into())).unwrap();
        b.touch("t", "x");
        assert!(b.flush(&|_, _| Some("2".into())).unwrap_err().contains("version"));
        assert_eq!(b.load("t").unwrap(), vec![("x".to_string(), "1".to_string())]);
        b.touch("t", "x");
        b.flush(&|_, _| Some("2".into())).unwrap();
        b.touch("t", "x");
        b.flush(&|_, _| None).unwrap();
        assert!(kv.get("t", "x").unwrap().is_none());
    }

    #[test]
    fn a_replica_with_its_database_down_hands_reads_and_writes_to_the_next() {
        let (down, good) = (fake::serve_unavailable(), fake::serve());
        let others: Others = Box::new(move |_: &str| vec![(fake::serve_unavailable().to_string(), "11".into(), None), (good.to_string(), "22".into(), None)]);
        let kv = StoreKv::with_others("kv-failover", "00".into(), Box::new(|| Ok(Vec::new())), Reach::At(down), others).unwrap();
        exercise(&*kv);
        // every replica down: one error that names them all, nothing pretends to have worked
        let none: Others = Box::new(move |_: &str| vec![(fake::serve_unavailable().to_string(), "11".into(), None)]);
        let kv = StoreKv::with_others("kv-failover", "00".into(), Box::new(|| Ok(Vec::new())), Reach::At(fake::serve_unavailable()), none).unwrap();
        let e = kv.put("t", "a", "1", None).unwrap_err();
        assert!(e.contains("every replica unavailable") && e.matches(UNAVAILABLE).count() == 2, "{e}");
    }

    /// A TCP relay to `to` whose open connections `drop_all` cuts, like a replica that restarted while idle.
    fn relay(to: std::net::SocketAddr) -> (std::net::SocketAddr, Arc<Mutex<Vec<std::net::TcpStream>>>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let open: Arc<Mutex<Vec<std::net::TcpStream>>> = Arc::new(Mutex::new(Vec::new()));
        let o = open.clone();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let u = std::net::TcpStream::connect(to).unwrap();
                o.lock().unwrap().extend([c.try_clone().unwrap(), u.try_clone().unwrap()]);
                let (mut c2, mut u2) = (c.try_clone().unwrap(), u.try_clone().unwrap());
                let (mut c, mut u) = (c, u);
                std::thread::spawn(move || { let _ = std::io::copy(&mut c, &mut u); });
                std::thread::spawn(move || { let _ = std::io::copy(&mut u2, &mut c2); });
            }
        });
        (addr, open)
    }

    #[test]
    fn a_write_after_the_replica_dropped_an_idle_connection_lands() {
        let (addr, open) = relay(fake::serve());
        let kv = StoreKv::new("kv-idle", "00".into(), Box::new(|| Ok(Vec::new())), Reach::At(addr)).unwrap();
        kv.put("t", "a", "1", None).unwrap();
        for s in open.lock().unwrap().drain(..) {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        std::thread::sleep(write_fresh() + std::time::Duration::from_millis(100));
        assert_eq!(kv.put("t", "a", "2", None).unwrap(), 2);
        assert_eq!(kv.get("t", "a").unwrap().map(|(v, _)| v).as_deref(), Some("2"));
    }

    #[test]
    fn mem_and_fake_agree() {
        exercise(&*MemKv::new());
        exercise(&*fake::store("kv-test"));
    }
}
