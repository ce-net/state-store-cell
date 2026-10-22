//! state.store cell: the engine (python `ce.state.store` ported to Rust, same tables and byte formats) behind two
//! doors: the typed ce-wire API (`state-store-api`) and the legacy JSON topic `state.store/ctl` that python clients
//! and remote replicas use. `state-store serve` runs both plus the replicator. See README.
mod auth;
mod db;
mod engine;
mod mesh;

use ce_wire::{Client, Server};
use engine::Store;
use serde_json::{json, Value};
use state_store_api::*;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

fn ce_key(name: &str) -> Result<String, String> {
    if let Ok(path) = std::env::var(format!("{name}_FILE")) {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(&path).map_err(|e| e.to_string())?.permissions().mode();
        if m & 0o077 != 0 {
            return Err(format!("{path} must be mode 600"));
        }
        return Ok(std::fs::read_to_string(path).map_err(|e| e.to_string())?.trim().into());
    }
    let bin = std::env::var("CE_KEY_BIN").unwrap_or_else(|_| "ce-key".to_string());
    let o = std::process::Command::new(bin).args(["get", name]).output().map_err(|e| e.to_string())?;
    let v = String::from_utf8_lossy(&o.stdout).trim().to_string();
    if !o.status.success() || v.is_empty() {
        return Err(format!("ce-key get {name} failed (keyring locked?): {}", String::from_utf8_lossy(&o.stderr).trim()));
    }
    Ok(v)
}

fn open_store(node_id: String, on_change: Box<dyn Fn(Value) + Send + Sync>, me: [u8; 32]) -> Result<Store, String> {
    use base64::Engine as _;
    let key = base64::engine::general_purpose::STANDARD.decode(ce_key("STATE_DB_DATA_KEY")?).map_err(|e| e.to_string())?;
    if key.len() < 32 {
        return Err("STATE_DB_DATA_KEY is shorter than 32 bytes".into());
    }
    let url = match std::env::var("STATE_STORE_DB") {
        Ok(u) => u,
        Err(_) => {
            let host = std::env::var("STATE_DB_HOST").unwrap_or_else(|_| "127.0.0.1".into());
            if !["127.0.0.1", "localhost", "::1"].contains(&host.as_str()) {
                return Err("state.store talks to Postgres on loopback only (a-host-is-closed-by-default)".into());
            }
            format!(
                "host={host} port={} dbname={} user=state_store password={}",
                std::env::var("STATE_DB_PORT").unwrap_or_else(|_| "5432".into()),
                std::env::var("STATE_DB_NAME").unwrap_or_else(|_| "state_store".into()),
                ce_key("STATE_DB_PASSWORD")?
            )
        }
    };
    Store::new(db::Db::open(&url)?, key, auth::Auth::new(me), node_id, on_change)
}

fn docj(v: &Value) -> Doc {
    Doc {
        key: v["key"].as_str().unwrap_or("").into(),
        value: v["value"].to_string(),
        seq: v["seq"].as_u64().unwrap_or(0),
        version: v["version"].as_u64().unwrap_or(0),
        deleted: v["deleted"].as_bool().unwrap_or(false),
    }
}
fn args(at: &Coll, key: &str) -> Result<Value, String> {
    check_name("app", &at.app)?;
    check_name("coll", &at.coll)?;
    Ok(json!({"app": at.app, "coll": at.coll, "key": key}))
}
fn cap(c: &str) -> Option<&str> {
    Some(c).filter(|c| !c.is_empty())
}

async fn on<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tokio::task::spawn_blocking(f).await.map_err(|e| e.to_string())?
}

async fn serve() -> Result<(), String> {
    let me = ce_gate::node_identity().map_err(|e| e.to_string())?;
    let node_id = mesh::hex(&me.node_id());
    let names = Arc::new(mesh::Names::from_env());
    let node = Arc::new(mesh::Node::new());
    let (n2, ch) = (node.clone(), names.changes.clone());
    let nid = node_id.clone();
    let mid = me.node_id();
    // Every change (a local write or a replicated one) bumps its app's count in `changed`; an open Watch waits on its own
    // app's count instead of polling, so a write to one app does not make every other app's watcher re-read.
    let (changed_tx, changed) = tokio::sync::watch::channel(Changed::default());
    let st = Arc::new(
        on(move || open_store(nid, Box::new(move |ev| {
            let app = ev["app"].as_str().unwrap_or("").to_string();
            changed_tx.send_modify(|m| {
                let c = m.entry(app).or_insert(0);
                *c = c.wrapping_add(1);
            });
            let n = n2.clone();
            let t = ch.clone();
            std::thread::spawn(move || n.publish(&t, &ev.to_string()));
        }), mid)).await?,
    );
    let errs: mesh::Errors = Arc::default();

    if legacy_on() {
        let (bell_tx, bell_rx) = mpsc::channel();
        let (n, s, nm, e) = (node.clone(), st.clone(), names.clone(), errs.clone());
        std::thread::spawn(move || mesh::serve_legacy(n, s, nm, e, bell_tx));
        let (n, s, nm, e) = (node.clone(), st.clone(), names.clone(), errs.clone());
        std::thread::spawn(move || mesh::replicate(n, s, nm, e, bell_rx));
        let (n, nm) = (node.clone(), names.clone());
        std::thread::spawn(move || loop {
            n.advertise(&nm.service);
            std::thread::sleep(Duration::from_secs(30));
        });
    }

    if std::env::var("STATE_STORE_TYPED").as_deref() == Ok("0") {
        return std::future::pending().await;
    }
    let gate = ce_gate::Gate::<StateStore>::new(me.node_id(), ce_gate::mesh_roots()).into_fn();
    let (s1, s2, s3, s4, s5, s6, s7, s8, s9) = (st.clone(), st.clone(), st.clone(), st.clone(), st.clone(), st.clone(), st.clone(), st.clone(), st.clone());
    Server::<StateStore>::new(gate)
        .on::<Get, _, _>(move |r: GetReq, who| { let s = s1.clone(); async move {
            check_key(&r.key)?;
            let a = args(&r.at, &r.key)?;
            on(move || Ok(Some(s.get(&a, cap(&r.cap), &who.name)?).filter(|v| !v.is_null()).map(|v| docj(&v)))).await
        } })
        .on::<Put, _, _>(move |r: PutReq, who| { let s = s2.clone(); async move {
            check_key(&r.key)?;
            check_value(&r.value)?;
            let value: Value = serde_json::from_str(&r.value).map_err(|e| format!("value is not JSON: {e}"))?;
            let mut a = args(&r.at, &r.key)?;
            a["value"] = value;
            if let Some(v) = r.if_version { a["if_version"] = json!(v); }
            on(move || Ok(docj(&if r.insert_only { s.insert(&a, cap(&r.cap), &who.name)? } else { s.put(&a, cap(&r.cap), &who.name)? }))).await
        } })
        .on::<Patch, _, _>(move |r: PatchReq, who| { let s = s3.clone(); async move {
            check_key(&r.key)?;
            check_value(&r.fields)?;
            let mut a = args(&r.at, &r.key)?;
            a["fields"] = serde_json::from_str(&r.fields).map_err(|e| format!("fields is not JSON: {e}"))?;
            on(move || Ok(docj(&s.patch(&a, cap(&r.cap), &who.name)?))).await
        } })
        .on::<Delete, _, _>(move |r: DeleteReq, who| { let s = s4.clone(); async move {
            check_key(&r.key)?;
            let a = args(&r.at, &r.key)?;
            on(move || s.delete(&a, cap(&r.cap), &who.name).map(|_| ())).await
        } })
        .on::<List, _, _>(move |r: ListReq, who| { let s = s5.clone(); async move {
            let mut a = args(&r.at, "x")?;
            a["prefix"] = json!(r.prefix);
            a["since"] = json!(r.since);
            a["limit"] = json!(r.limit.clamp(1, MAX_PAGE));
            on(move || { let v = s.list(&a, cap(&r.cap), &who.name, Some(r.include_deleted))?; Ok(page_of(&v)) }).await
        } })
        .on::<Health, _, _>(move |_: (), _| { let s = s6.clone(); async move {
            on(move || { let h = s.health()?; Ok(StoreHealth { backend: h["backend"].as_str().unwrap_or("").into(), records: h["records"].as_u64().unwrap_or(0), head_seq: h["head_seq"].as_u64().unwrap_or(0), audit_rows: h["audit_rows"].as_u64().unwrap_or(0), schema_hash: <StateStore as ce_wire::Api>::SCHEMA }) }).await
        } })
        .on::<Schema, _, _>(move |r: SchemaReq, who| { let s = s7.clone(); async move {
            check_name("app", &r.app)?;
            on(move || Ok(Some(s.get_schema(&json!({"app": r.app}), cap(&r.cap), &who.name)?).filter(|v| !v.is_null()).map(|v| v.to_string()))).await
        } })
        .on::<SchemaPut, _, _>(move |r: SchemaPutReq, who| { let s = s8.clone(); async move {
            check_name("app", &r.app)?;
            let sc: Value = serde_json::from_str(&r.schema).map_err(|e| format!("schema is not JSON: {e}"))?;
            on(move || s.put_schema(&json!({"app": r.app, "schema": sc}), cap(&r.cap), &who.name).map(|_| ())).await
        } })
        .stream::<Watch, _, _>(move |r: WatchReq, who, sink| { let s = s9.clone(); let changed = changed.clone(); async move {
            let mut a = args(&r.at, "x")?;
            let app = r.at.app.clone();
            let read = move |since: u64| {
                a["since"] = json!(since);
                a["limit"] = json!(MAX_PAGE);
                let (s2, a2, c2, w2) = (s.clone(), a.clone(), r.cap.clone(), who.name.clone());
                on(move || Ok(page_of(&s2.changes(&a2, cap(&c2), &w2)?)))
            };
            watch_pages(&app, r.since, changed, read, |d| sink.send(d).map_err(|e| e.to_string())).await
        } })
        .serve_door()
        .await
        .map_err(|e| e.to_string())
}

/// The legacy mesh face (serve_legacy, the replicator, advertise): on unless `STATE_STORE_LEGACY=0`, or, without that
/// env, `~/.config/ce-state/legacy` holds `0` (the door gives a cell no env; a node where the Python state.store server
/// already answers the legacy topic and replicates turns it off here so two servers do not do both).
fn legacy_on() -> bool {
    match std::env::var("STATE_STORE_LEGACY") {
        Ok(v) if !v.trim().is_empty() => v.trim() != "0",
        _ => std::fs::read_to_string(format!("{}/.config/ce-state/legacy", std::env::var("HOME").unwrap_or_default())).map_or(true, |v| v.trim() != "0"),
    }
}

/// The longest an idle Watch waits before it reads again without a change signal.
const WATCH_IDLE: Duration = Duration::from_secs(5);

/// Changes seen per app (cumulative, wrapping): what an open Watch waits on.
type Changed = std::collections::HashMap<String, u64>;

/// One Watch on `app`: send every change after `since` in seq order, page by page from this watcher's own cursor; when
/// caught up, wait until `app`'s count in `changed` moves (a local or replicated write to it) or [`WATCH_IDLE`] passes (a
/// writer outside this process), never a busy poll. Another app's write wakes the wait but costs no read. A change
/// landing between the read and the wait is still seen (its count is taken before each read).
async fn watch_pages<R, F>(app: &str, mut since: u64, mut changed: tokio::sync::watch::Receiver<Changed>, mut read: R, mut send: impl FnMut(&Doc) -> Result<(), String>) -> Result<(), String>
where
    R: FnMut(u64) -> F,
    F: std::future::Future<Output = Result<Page, String>>,
{
    loop {
        let seen = changed.borrow_and_update().get(app).copied();
        let p = read(since).await?;
        for d in &p.docs {
            since = since.max(d.seq);
            send(d)?;
        }
        if p.next.is_none() {
            let until = tokio::time::Instant::now() + WATCH_IDLE;
            while changed.borrow().get(app).copied() == seen {
                if tokio::time::timeout_at(until, changed.changed()).await.map_or(true, |r| r.is_err()) {
                    break;
                }
            }
        }
    }
}

fn page_of(v: &Value) -> Page {
    Page { docs: v["items"].as_array().map(|a| a.iter().map(docj).collect()).unwrap_or_default(), next: v["next"].as_u64() }
}

/// `state-store verify`: the audit chain of the database this cell would serve, checked from row 1.
fn verify() -> Result<(), String> {
    let me = ce_gate::node_identity().map_err(|e| e.to_string())?;
    let st = open_store(mesh::hex(&me.node_id()), Box::new(|_| {}), me.node_id())?;
    let breaks = st.verify_audit()?;
    let baseline: usize = std::env::var("STATE_STORE_AUDIT_BASELINE").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let (good, bad) = st.verify_rows()?;
    println!("{} audit_breaks={breaks} baseline={baseline} rows_decrypt_ok={good} rows_bad={bad}", st.health()?);
    if breaks <= baseline && bad == 0 { Ok(()) } else { Err("audit chain grew breaks or rows do not decrypt".into()) }
}

async fn cli(a: Vec<String>) -> Result<(), String> {
    let token = ce_gate::self_proof::<StateStore>(3600).map_err(|e| e.to_string())?;
    let c = Client::<StateStore>::connect(("127.0.0.1", ce_wire::door_port()), token).await.map_err(|e| format!("{e:?}"))?;
    let g = |i: usize| a.get(i).cloned().unwrap_or_default();
    let at = Coll { app: g(1), coll: g(2) };
    let n16 = hex_prefix();
    let cp = std::env::var("STATE_STORE_CAP").ok().or_else(|| mesh::wallet_cap(&format!("state.store:{}@{n16}", at.app))).or_else(|| mesh::wallet_cap(&format!("state.store:{}", at.app))).unwrap_or_default();
    if cp.is_empty() && a[0] != "health" {
        return Err(format!("no capability sent: no grant for {} in the wallet (state.store:{0}@{n16} or state.store:{0}) and ce-iam has none; set STATE_STORE_CAP", at.app));
    }
    let e = |e: ce_wire::WireError| format!("{e:?}");
    match a[0].as_str() {
        "get" => println!("{:?}", c.call::<Get>(&GetReq { at, key: g(3), cap: cp }).await.map_err(e)?),
        "put" => println!("{:?}", c.call::<Put>(&PutReq { at, key: g(3), value: g(4), if_version: a.get(5).and_then(|v| v.parse().ok()), insert_only: false, cap: cp }).await.map_err(e)?),
        "del" => c.call::<Delete>(&DeleteReq { at, key: g(3), cap: cp }).await.map_err(e)?,
        "list" => println!("{:?}", c.call::<List>(&ListReq { at, prefix: g(3), since: 0, limit: 50, include_deleted: false, cap: cp }).await.map_err(e)?),
        "health" => println!("{:?}", c.call::<Health>(&()).await.map_err(e)?),
        _ => return Err("usage: state-store serve | verify | health | get A C K | put A C K JSON [ver] | del A C K | list A C [prefix]".into()),
    }
    Ok(())
}

fn hex_prefix() -> String {
    ce_gate::node_identity().map(|i| mesh::hex(&i.node_id())[..16].to_string()).unwrap_or_default()
}

/// `state-store bench HOST:PORT [APP COLL KEY] [--n 10] [--fresh 3]`: read latency to one state.store door, the way a
/// remote reader sees it. Times `Health` (no cap) and, with APP COLL KEY, `Get` (cap from the wallet like `get`):
/// `n` calls on one held connection, then `fresh` calls that each open a new connection (connect + hello + call).
/// Prints every sample and p50/max in ms. For diagnosing a slow long-distance link.
async fn bench(a: Vec<String>) -> Result<(), String> {
    let mut pos = vec![];
    let (mut n, mut fresh) = (10usize, 3usize);
    let mut node16 = hex_prefix();
    let a: Vec<String> = a.into_iter().skip(1).collect();
    let mut it = a.iter();
    while let Some(x) = it.next() {
        match x.as_str() {
            "--n" => n = it.next().and_then(|v| v.parse().ok()).ok_or("--n N")?,
            "--fresh" => fresh = it.next().and_then(|v| v.parse().ok()).ok_or("--fresh N")?,
            "--node16" => node16 = it.next().cloned().ok_or("--node16 <first 16 hex of the replica's node id>")?,
            _ => pos.push(x.clone()),
        }
    }
    let addr = pos.first().cloned().ok_or("usage: state-store bench HOST:PORT [APP COLL KEY] [--node16 HEX] [--n 10] [--fresh 3]")?;
    let (host, port) = addr.rsplit_once(':').ok_or("HOST:PORT")?;
    let port: u16 = port.parse().map_err(|_| "bad port")?;
    let get = (pos.len() >= 4).then(|| {
        let at = Coll { app: pos[1].clone(), coll: pos[2].clone() };
        let n16 = node16.clone();
        let cap = std::env::var("STATE_STORE_CAP").ok().or_else(|| mesh::wallet_cap(&format!("state.store:{}@{n16}", at.app)))
            .or_else(|| mesh::wallet_cap(&format!("state.store:{}", at.app))).unwrap_or_default();
        GetReq { at, key: pos[3].clone(), cap }
    });
    // a remote replica trusts only grants rooted at its own key: the hello is this node's proof over its door grant
    // (kv.rs replica_hello), else this node's self proof (enough on the replica's own machine)
    // (kv.rs replica_hello over the replica's door grant `state.store:hello@<node16>`), else this node's self proof
    // a hello is single use (the door refuses a replay): sign a fresh one per connection
    let hello = state_store_api::kv::hello_cap(&node16);
    let token = || -> Result<Vec<u8>, String> {
        Ok(match &hello {
            Some(h) => ce_gate::proof::<StateStore>(&ce_gate::node_identity().map_err(|e| e.to_string())?,
                &ce_gate::chain_from_hex(h.trim()).map_err(|e| format!("hello grant: {e:?}"))?),
            None => ce_gate::self_proof::<StateStore>(3600).map_err(|e| e.to_string())?,
        })
    };
    let e = |e: ce_wire::WireError| format!("{e:?}");
    let ms = |t: std::time::Instant| t.elapsed().as_secs_f64() * 1000.0;
    let report = |what: &str, v: &mut Vec<f64>| {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p50 = v.get(v.len() / 2).copied().unwrap_or(0.0);
        println!("{what}: n={} p50={p50:.0} ms max={:.0} ms  [{}]", v.len(), v.last().copied().unwrap_or(0.0),
            v.iter().map(|x| format!("{x:.0}")).collect::<Vec<_>>().join(" "));
    };
    let t = std::time::Instant::now();
    let c = Client::<StateStore>::connect((host, port), token()?).await.map_err(|e| format!("connect: {e:?}"))?;
    println!("connect+hello: {:.0} ms", ms(t));
    let (mut h, mut g) = (vec![], vec![]);
    for _ in 0..n {
        let t = std::time::Instant::now();
        c.call::<Health>(&()).await.map_err(e)?;
        h.push(ms(t));
        if let Some(req) = &get {
            let t = std::time::Instant::now();
            c.call::<Get>(req).await.map_err(e)?;
            g.push(ms(t));
        }
    }
    report("held Health", &mut h);
    if get.is_some() { report("held Get", &mut g); }
    let mut f = vec![];
    for _ in 0..fresh {
        let t = std::time::Instant::now();
        let c = Client::<StateStore>::connect((host, port), token()?).await.map_err(|e| format!("connect: {e:?}"))?;
        match &get { Some(req) => { c.call::<Get>(req).await.map_err(e)?; } None => { c.call::<Health>(&()).await.map_err(e)?; } }
        f.push(ms(t));
    }
    report(if get.is_some() { "fresh connect+Get" } else { "fresh connect+Health" }, &mut f);
    Ok(())
}

/// A mesh server holds a socket per peer and per client: lift the soft open-files limit to the hard one at start. The
/// default 1024 ran out under load ("Too many open files", then every kv call Closed).
fn raise_nofile() {
    // SAFETY: plain libc calls on a local struct
    unsafe {
        let mut l = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut l) == 0 && l.rlim_cur < l.rlim_max {
            l.rlim_cur = l.rlim_max.min(1 << 20);
            libc::setrlimit(libc::RLIMIT_NOFILE, &l);
        }
    }
}

fn main() {
    raise_nofile();
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("tokio");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let r = match a.first().map(String::as_str) {
        Some("serve") => rt.block_on(serve()),
        Some("verify") => verify(),
        Some("bench") => rt.block_on(bench(a)),
        Some(_) => rt.block_on(cli(a)),
        None => Err("usage: state-store serve | verify | health | get|put|del|list".into()),
    };
    if let Err(e) = r {
        eprintln!("state-store: {e}");
        std::process::exit(1);
    }
}

#[allow(dead_code)]
type _Unused = Mutex<()>;

#[cfg(test)]
mod watch_tests {
    use super::*;

    fn doc(seq: u64) -> Doc {
        Doc { key: format!("k{seq}"), value: "{}".into(), seq, version: 1, deleted: false }
    }

    /// A fake changes(): the docs after `since`, at most `page` per call, in seq order.
    fn reader(log: Arc<Mutex<Vec<Doc>>>, page: usize) -> impl FnMut(u64) -> std::future::Ready<Result<Page, String>> {
        move |since| {
            let l = log.lock().unwrap();
            let after: Vec<Doc> = l.iter().filter(|d| d.seq > since).cloned().collect();
            let next = (after.len() > page).then(|| after[page - 1].seq);
            std::future::ready(Ok(Page { docs: after.into_iter().take(page).collect(), next }))
        }
    }

    fn bump(tx: &tokio::sync::watch::Sender<Changed>, app: &str) {
        tx.send_modify(|m| *m.entry(app.to_string()).or_insert(0) += 1);
    }

    #[tokio::test]
    async fn another_apps_write_costs_no_read() {
        let log = Arc::new(Mutex::new(vec![]));
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (tx, rx) = tokio::sync::watch::channel(Changed::default());
        let r2 = reads.clone();
        let mut inner = reader(log.clone(), 10);
        let read = move |since| {
            r2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            inner(since)
        };
        let w = tokio::spawn(watch_pages("a", 0, rx, read, |_| Ok(())));
        tokio::time::sleep(Duration::from_millis(100)).await; // caught up and waiting
        let before = reads.load(std::sync::atomic::Ordering::SeqCst);
        for _ in 0..20 {
            bump(&tx, "b");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), before, "app b's writes made app a's watcher read");
        bump(&tx, "a");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), before + 1);
        w.abort();
    }

    #[tokio::test]
    async fn open_watch_sees_a_write_at_once() {
        let log = Arc::new(Mutex::new(vec![]));
        let (tx, rx) = tokio::sync::watch::channel(Changed::default());
        let (got_tx, mut got) = tokio::sync::mpsc::unbounded_channel();
        let w = tokio::spawn(watch_pages("a", 0, rx, reader(log.clone(), 10), move |d| got_tx.send(d.seq).map_err(|e| e.to_string())));
        tokio::time::sleep(Duration::from_millis(100)).await; // the watcher is caught up and waiting
        log.lock().unwrap().push(doc(1));
        bump(&tx, "a");
        let t = std::time::Instant::now();
        let seq = tokio::time::timeout(Duration::from_secs(2), got.recv()).await.expect("seen within 2 s, not the 5 s idle read");
        assert_eq!(seq, Some(1));
        assert!(t.elapsed() < Duration::from_millis(500), "woken by the change, took {:?}", t.elapsed());
        w.abort();
    }

    #[tokio::test]
    async fn behind_watcher_gets_every_change_in_order() {
        let log = Arc::new(Mutex::new((1..=25).map(doc).collect::<Vec<_>>()));
        let (tx, rx) = tokio::sync::watch::channel(Changed::default());
        let (got_tx, mut got) = tokio::sync::mpsc::unbounded_channel();
        let w = tokio::spawn(watch_pages("a", 5, rx, reader(log.clone(), 4), move |d| got_tx.send(d.seq).map_err(|e| e.to_string())));
        for seq in 26..=30 {
            log.lock().unwrap().push(doc(seq));
            bump(&tx, "a");
        }
        let mut seen = vec![];
        while seen.len() < 25 {
            seen.push(tokio::time::timeout(Duration::from_secs(2), got.recv()).await.expect("all within 2 s").unwrap());
        }
        assert_eq!(seen, (6..=30).collect::<Vec<u64>>());
        w.abort();
    }
}
