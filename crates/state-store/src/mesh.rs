//! The ce node's mesh API (HTTP on 127.0.0.1:8844) as the python service uses it: the legacy JSON topic
//! `state.store/ctl` answered for python clients and remote replicas, the `state.store/changes` feed, and the
//! replicator that pulls from and pushes to every other provider of `ce.state.store`.
use crate::engine::Store;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())).collect()
}

pub struct Node {
    api: String,
}

impl Node {
    pub fn new() -> Node {
        Node { api: std::env::var("CE_API_URL").unwrap_or_else(|_| "http://127.0.0.1:8844".into()) }
    }
    fn token() -> String {
        if let Ok(t) = std::env::var("CE_API_TOKEN") {
            return t.trim().into();
        }
        let dir = ce_wire::ce_data_dir().to_string_lossy().into_owned();
        std::fs::read_to_string(format!("{dir}/api.token")).map(|t| t.trim().into()).unwrap_or_default()
    }
    fn post(&self, path: &str, body: Value, secs: u64) -> Result<Value, String> {
        let r = ureq::post(&format!("{}{path}", self.api))
            .set("Authorization", &format!("Bearer {}", Self::token()))
            .timeout(Duration::from_secs(secs))
            .send_json(body)
            .map_err(|e| e.to_string())?;
        Ok(r.into_json().unwrap_or(Value::Null))
    }
    pub fn subscribe(&self, topic: &str) -> Result<(), String> {
        self.post("/mesh/subscribe", json!({"topic": topic}), 10).map(|_| ())
    }
    pub fn publish(&self, topic: &str, payload: &str) {
        let _ = self.post("/mesh/publish", json!({"topic": topic, "payload_hex": hex(payload.as_bytes())}), 5);
    }
    pub fn reply(&self, token: u64, payload: &str) -> Result<(), String> {
        self.post("/mesh/reply", json!({"token": token, "payload_hex": hex(payload.as_bytes())}), 10).map(|_| ())
    }
    pub fn advertise(&self, service: &str) {
        let _ = self.post("/discovery/advertise", json!({"service": service}), 10);
    }
    pub fn find(&self, service: &str) -> Vec<String> {
        let enc: String = service.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect();
        ureq::get(&format!("{}/discovery/find/{enc}", self.api))
            .set("Authorization", &format!("Bearer {}", Self::token()))
            .timeout(Duration::from_secs(10))
            .call()
            .ok()
            .and_then(|r| r.into_json::<Value>().ok())
            .and_then(|v| v["providers"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()))
            .unwrap_or_default()
    }
    /// One JSON op to `to`'s service on `topic`. Never resent here: a write that timed out may have landed.
    pub fn call(&self, to: &str, topic: &str, op: &str, args: Value, cap: Option<&str>, timeout_ms: u64) -> Result<Value, String> {
        let frame = json!({"op": op, "args": args, "cap": cap});
        let r = self.post("/mesh/request", json!({"to": to, "topic": topic, "payload_hex": hex(frame.to_string().as_bytes()), "timeout_ms": timeout_ms}), timeout_ms / 1000 + 5)?;
        let reply: Value = serde_json::from_slice(&unhex(r["payload_hex"].as_str().unwrap_or(""))?).map_err(|e| e.to_string())?;
        if let Some(e) = reply.get("error") {
            return Err(format!("{op}: {}", e.as_str().unwrap_or("error")));
        }
        Ok(reply.get("result").cloned().unwrap_or(reply))
    }
    /// Inbound messages for `topics`, forever (reconnects with backoff). `f(from, topic, payload, reply_token)`.
    pub fn serve(&self, topics: &[String], mut f: impl FnMut(String, String, Vec<u8>, Option<u64>)) {
        let mut back = 500u64;
        loop {
            for t in topics {
                let _ = self.subscribe(t);
            }
            let url = format!("{}/mesh/messages/stream?topics={}", self.api, topics.join(",").replace('/', "%2F"));
            match ureq::get(&url).set("Authorization", &format!("Bearer {}", Self::token())).set("Accept", "text/event-stream").timeout(Duration::from_secs(3600)).call() {
                Ok(resp) => {
                    back = 500;
                    let mut data = String::new();
                    for line in BufReader::new(resp.into_reader()).lines() {
                        let Ok(line) = line else { break };
                        if line.is_empty() {
                            if let Ok(r) = serde_json::from_str::<Value>(&data) {
                                f(
                                    r["from"].as_str().unwrap_or("").into(),
                                    r["topic"].as_str().unwrap_or("").into(),
                                    unhex(r["payload_hex"].as_str().unwrap_or("")).unwrap_or_default(),
                                    r["reply_token"].as_u64(),
                                );
                            }
                            data.clear();
                        } else if let Some(d) = line.strip_prefix("data:") {
                            data.push_str(d.trim_start());
                        }
                    }
                }
                Err(e) => eprintln!("state-store: mesh stream: {e}"),
            }
            std::thread::sleep(Duration::from_millis(back));
            back = (back * 2).min(10_000);
        }
    }
}

pub struct Names {
    pub service: String,
    pub topic: String,
    pub changes: String,
}
impl Names {
    pub fn from_env() -> Names {
        let g = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.into());
        Names { service: g("STATE_STORE_SERVICE", "ce.state.store"), topic: g("STATE_STORE_TOPIC", "state.store/ctl"), changes: g("STATE_STORE_CHANGES", "state.store/changes") }
    }
}

/// The grant held under `label` in this node's ce-iam wallet. Read from `<ce data dir>/wallet.toml` directly, so a
/// caller whose PATH lacks `ce-iam` (non-login ssh, cron, systemd) still presents it; before this the CLI sent an empty
/// cap there and the engine refused `not authorized` with a valid grant. `ce-iam wallet show` stays the fallback.
pub fn wallet_cap(label: &str) -> Option<String> {
    std::fs::read_to_string(ce_wire::ce_data_dir().join("wallet.toml")).ok().and_then(|t| wallet_entry_cap(&t, label)).or_else(|| ce_iam_wallet_cap(label))
}

/// `cap` of `[entries."<label>"]` in wallet.toml text (the layout `ce-iam wallet` writes).
pub fn wallet_entry_cap(toml: &str, label: &str) -> Option<String> {
    let head = format!("[entries.\"{label}\"]");
    let lines = toml.lines().map(str::trim).skip_while(|l| *l != head).skip(1);
    lines
        .take_while(|l| !l.starts_with('['))
        .find_map(|l| l.strip_prefix("cap")?.trim_start().strip_prefix('=')?.trim().strip_prefix('"')?.strip_suffix('"').map(String::from))
        .filter(|c| c.len() > 64 && c.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn ce_iam_wallet_cap(label: &str) -> Option<String> {
    // PATH first, then where ce-iam installs itself (a non-login shell or systemd PATH often lacks ~/.local/bin).
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from).unwrap_or_default();
    let out = [std::path::PathBuf::from("ce-iam"), home.join(".local/bin/ce-iam"), ce_wire::ce_data_dir().join("bin/ce-iam")]
        .iter()
        .find_map(|b| std::process::Command::new(b).args(["wallet", "show", label]).output().ok())?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| l.split_whitespace().last()).find(|w| w.len() > 64 && w.bytes().all(|b| b.is_ascii_hexdigit())).map(String::from)
}

pub type Errors = Arc<Mutex<HashMap<String, String>>>;

fn dispatch(st: &Store, errs: &Errors, op: &str, payload: &Value, sender: &str) -> Value {
    let args = payload.get("args").cloned().unwrap_or_else(|| {
        let mut p = payload.clone();
        if let Some(o) = p.as_object_mut() {
            o.remove("op");
        }
        p
    });
    let cap = payload.get("cap").and_then(Value::as_str);
    let r = match op {
        "state.get" => st.get(&args, cap, sender),
        "state.put" => st.put(&args, cap, sender),
        "state.insert" => st.insert(&args, cap, sender),
        "state.patch" => st.patch(&args, cap, sender),
        "state.delete" => st.delete(&args, cap, sender),
        "state.list" => st.list(&args, cap, sender, None),
        "state.changes" => st.changes(&args, cap, sender),
        "state.schema" => st.get_schema(&args, cap, sender),
        "state.schema.put" => st.put_schema(&args, cap, sender),
        "state.repl.pull" => st.repl_pull(&args, cap, sender),
        "state.repl.since" => st.repl_since(&args, cap, sender),
        "state.repl.push" => st.repl_push(&args, cap, sender),
        "state.health" => st.health().map(|mut h| {
            let pe: serde_json::Map<String, Value> = errs.lock().unwrap().iter().map(|(k, v)| (k.chars().take(12).collect(), json!(v.chars().take(120).collect::<String>()))).collect();
            h["replication"] = json!("on");
            h["peer_errors"] = Value::Object(pe);
            h["engine"] = json!("rust");
            h
        }),
        "describe" => Ok(json!({"service": "ce.state.store", "engine": "rust", "ops": ["describe", "state.get", "state.put", "state.insert", "state.patch", "state.delete", "state.list", "state.changes", "state.schema", "state.schema.put", "state.repl.pull", "state.repl.since", "state.repl.push", "state.health"]})),
        _ => Err(format!("unknown op '{op}'; ask `describe`")),
    };
    match r {
        Ok(v) => v,
        Err(e) => json!({"error": format!("{op}: {e}")}),
    }
}

/// Answer the legacy JSON topic with 8 workers and a bounded queue; ring the replicator on a peer's change.
pub fn serve_legacy(node: Arc<Node>, st: Arc<Store>, names: Arc<Names>, errs: Errors, bell: mpsc::Sender<()>) {
    let (tx, rx) = mpsc::sync_channel::<(String, Value, String, u64)>(256);
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..8 {
        let (rx, st, node, errs) = (rx.clone(), st.clone(), node.clone(), errs.clone());
        std::thread::spawn(move || loop {
            let Ok((op, payload, from, token)) = rx.lock().unwrap().recv() else { return };
            let out = dispatch(&st, &errs, &op, &payload, &from);
            if let Err(e) = node.reply(token, &out.to_string()) {
                eprintln!("state-store: reply failed: {e}");
            }
        });
    }
    let topics = vec![names.topic.clone(), names.changes.clone()];
    node.clone().serve(&topics, |from, topic, payload, token| {
        if topic == names.changes {
            if let Ok(ev) = serde_json::from_slice::<Value>(&payload) {
                if ev["node"].as_str().is_some_and(|n| !n.is_empty() && n != st.node_id) {
                    let _ = bell.send(());
                }
            }
            return;
        }
        if topic != names.topic {
            return;
        }
        let Some(token) = token else { return };
        let Ok(p) = serde_json::from_slice::<Value>(&payload) else {
            let _ = node.reply(token, &json!({"error": "payload must be JSON: {\"op\": ...}"}).to_string());
            return;
        };
        let op = p["op"].as_str().unwrap_or("").to_string();
        if tx.try_send((op, p, from, token)).is_err() {
            let _ = node.reply(token, &json!({"error": "ce.state.store is at capacity; retry shortly"}).to_string());
        }
    });
}

/// Pulls every other provider into this replica and pushes ours to it (python `Replicator`).
pub fn replicate(node: Arc<Node>, st: Arc<Store>, names: Arc<Names>, errs: Errors, bell: mpsc::Receiver<()>) {
    let every = Duration::from_secs_f64(std::env::var("STATE_STORE_PULL_EVERY").ok().and_then(|v| v.parse().ok()).unwrap_or(5.0));
    let mut caps: HashMap<String, Option<String>> = HashMap::new();
    let mut limit: HashMap<String, i64> = HashMap::new();
    // a peer that keeps failing (a replica behind a lossy long-distance link: 504/502/EOF from the mesh, 70+ reports a day)
    // is tried less often, so its 30 s timeouts stop holding up the healthy peers and the log says it once
    let mut down: HashMap<String, Down> = HashMap::new();
    loop {
        let _ = bell.recv_timeout(every);
        while bell.try_recv().is_ok() {}
        for peer in node.find(&names.service).into_iter().filter(|p| !p.is_empty() && *p != st.node_id) {
            if down.get(&peer).is_some_and(|d| Instant::now() < d.next) { continue }
            let cap = caps
                .entry(peer.clone())
                .or_insert_with(|| wallet_cap(&format!("state.store:replica@{}", &peer[..16.min(peer.len())])).or_else(|| std::env::var("STATE_STORE_REPLICA_CAP").ok().filter(|v| !v.trim().is_empty())).or_else(|| wallet_cap("state.store:replica")))
                .clone();
            let Some(cap) = cap else {
                caps.remove(&peer);
                errs.lock().unwrap().insert(peer.clone(), "no state.store:replica grant from this peer".into());
                continue;
            };
            let short = &peer[..12.min(peer.len())];
            let mut failed = None;
            for verb in ["pull", "push"] {
                let k = if verb == "pull" { peer.clone() } else { format!("push:{peer}") };
                let r = if verb == "pull" { pull(&node, &st, &names, &peer, &cap, &mut limit) } else { push(&node, &st, &names, &peer, &cap, &mut limit) };
                match r {
                    Ok(_) => {
                        errs.lock().unwrap().remove(&k);
                    }
                    Err(e) => {
                        errs.lock().unwrap().insert(k, e.clone());
                        failed = Some(format!("{verb} {short} failed: {e}"));
                        break;
                    }
                }
            }
            match failed {
                None => {
                    if let Some(d) = down.remove(&peer).filter(|d| d.said.is_some()) {
                        eprintln!("state-store: {short} answers again after {} rounds without an answer", d.fails);
                    }
                }
                Some(line) => {
                    let d = down.entry(peer.clone()).or_insert_with(|| Down { fails: 0, next: Instant::now(), said: None });
                    d.fails += 1;
                    d.next = Instant::now() + backoff(d.fails);
                    // missed rounds are normal over a lossy long-distance link (peers usually answer again within 30 s, and
                    // one replica missed 3 in a row ~5 times an hour); from the sixth in a row
                    // (about 5 min without an answer) it is worth a line, then every 30 min
                    if d.fails >= QUIET_ROUNDS && d.said.is_none_or(|t| t.elapsed() >= Duration::from_secs(1800)) {
                        let tail = if d.fails > QUIET_ROUNDS { format!(" (still, {} rounds; next try in {} s)", d.fails, backoff(d.fails).as_secs()) } else { String::new() };
                        eprintln!("state-store: {line}{tail}");
                        d.said = Some(Instant::now());
                    }
                }
            }
        }
    }
}

/// Failed rounds in a row before the log names a peer: 18 = about 15 min (30 s calls plus 5..80 s backoff).
/// 6 (~5 min) still paged for a lossy link's drops, which heal after 6-8 rounds several times a morning.
pub const QUIET_ROUNDS: u32 = 18;

/// A peer whose last rounds failed: how many, when to try it next, when the log last said so.
struct Down { fails: u32, next: Instant, said: Option<Instant> }

/// Wait before the next try after `fails` failed rounds in a row: 5 s, 10 s, 20 s ... at most 5 min.
pub fn backoff(fails: u32) -> Duration {
    Duration::from_secs((5u64 << fails.saturating_sub(1).min(6)).min(300))
}

fn pull(node: &Node, st: &Store, names: &Names, peer: &str, cap: &str, limit: &mut HashMap<String, i64>) -> Result<i64, String> {
    let (mut n, mut first) = (0, true);
    loop {
        let lim = *limit.get(peer).unwrap_or(&100);
        let args = json!({"since": st.cursor(peer)?, "limit": lim, "max_bytes": lim * 640, "schemas": if first { st.schema_hlcs()? } else { json!(false) }});
        let reply = match node.call(peer, &names.topic, "state.repl.pull", args, Some(cap), 30_000) {
            Ok(r) => r,
            Err(e) => {
                limit.insert(peer.into(), (lim / 2).max(1));
                return Err(e);
            }
        };
        limit.insert(peer.into(), (lim * 2).min(500));
        first = false;
        n += st.repl_apply(peer, &reply)?;
        if !reply["more"].as_bool().unwrap_or(false) {
            return Ok(n);
        }
    }
}

fn push(node: &Node, st: &Store, names: &Names, peer: &str, cap: &str, limit: &mut HashMap<String, i64>) -> Result<i64, String> {
    let at = node.call(peer, &names.topic, "state.repl.since", json!({}), Some(cap), 15_000)?;
    let mut since = at["since"].as_i64().unwrap_or(0);
    let have = at.get("schemas").cloned().unwrap_or(json!(true));
    let (mut n, mut first) = (0, true);
    let lk = format!("push:{peer}");
    loop {
        let lim = *limit.get(&lk).unwrap_or(&100);
        let page = st.repl_rows(since, Some(lim), Some(lim * 640), Some(peer), if first { &have } else { &json!(false) }, Some(peer))?;
        if page["rows"].as_array().is_none_or(Vec::is_empty) && page["last"].as_i64() == Some(since) {
            return Ok(n);
        }
        let r = match node.call(peer, &names.topic, "state.repl.push", json!({"since": since, "reply": page}), Some(cap), 30_000) {
            Ok(r) => r,
            Err(e) => {
                limit.insert(lk, (lim / 2).max(1));
                return Err(e);
            }
        };
        limit.insert(lk.clone(), (lim * 2).min(500));
        first = false;
        n += r["applied"].as_i64().unwrap_or(0);
        if r["stale"].as_bool().unwrap_or(false) || r["since"].as_i64() == Some(since) || !page["more"].as_bool().unwrap_or(false) {
            return Ok(n);
        }
        since = r["since"].as_i64().unwrap_or(since);
    }
}

#[cfg(test)]
mod tests {
    use super::wallet_entry_cap;
    const W: &str = "[entries.\"state.store:cells@aaaabbbbccccdddd\"]\nnode_id = \"aa\"\ncap = \"0100abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\"\n\n[entries.\"state.store:repl-probe@aaaabbbbccccdddd\"]\nnode_id = \"aaaa\"\ncap = \"0100000000000000aaaabbbbccccdddd00112233445566778899aabbccddeeff0011223344556677ff\"\n";

    // The bug: over non-login ssh `ce-iam` is not on PATH, the CLI sent an empty cap and a valid grant was refused.
    // The wallet is now read without any subprocess, so the right grant is found from any environment.
    #[test]
    fn backoff_doubles_to_five_minutes() {
        let s: Vec<u64> = (1..=9).map(|f| super::backoff(f).as_secs()).collect();
        assert_eq!(s, vec![5, 10, 20, 40, 80, 160, 300, 300, 300]);
    }

    #[test]
    fn reads_the_labelled_grant_without_ce_iam() {
        assert_eq!(wallet_entry_cap(W, "state.store:repl-probe@aaaabbbbccccdddd").as_deref(), Some("0100000000000000aaaabbbbccccdddd00112233445566778899aabbccddeeff0011223344556677ff"));
        assert!(wallet_entry_cap(W, "state.store:cells@aaaabbbbccccdddd").unwrap().starts_with("0100abcdef"));
        assert_eq!(wallet_entry_cap(W, "state.store:repl-probe"), None);
        assert_eq!(wallet_entry_cap("", "x"), None);
    }
}
