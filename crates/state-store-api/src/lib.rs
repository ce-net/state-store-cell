//! state.store: shared app state. Docs live at (app, coll, key); a value is JSON text. Types only: depend on this
//! crate to call the cell. The data is the python `ce.state.store` service's (same Postgres/SQLite, same AES-GCM
//! rows, same replication); this API is its typed front door.
//!
//! Limits are constants here and checked by the cell before any call reaches storage; a caller can check first
//! with `Limits::check_*`.

/// Name rule of the store: `app` and `coll` match `[A-Za-z0-9._-]{1,64}`.
pub const MAX_NAME: usize = 64;
/// Longest key in bytes.
pub const MAX_KEY: usize = 512;
/// Largest value in bytes. Rows must stay under 2 KB: a slow intercontinental mesh link drops bigger ones.
pub const MAX_VALUE: usize = 2000;
// (the engine itself accepts 4 MiB sealed rows for python callers; this API holds the 2 KB line.)
/// Most docs one List or Watch page returns.
pub const MAX_PAGE: u32 = 500;

pub fn check_name(what: &str, s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > MAX_NAME || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
        return Err(format!("bad {what}: 1..={MAX_NAME} of [A-Za-z0-9._-]"));
    }
    Ok(())
}
pub fn check_key(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > MAX_KEY {
        return Err(format!("bad key: 1..={MAX_KEY} bytes"));
    }
    Ok(())
}
pub fn check_value(s: &str) -> Result<(), String> {
    if s.len() > MAX_VALUE {
        return Err(format!("value is {} bytes, the limit is {MAX_VALUE}", s.len()));
    }
    Ok(())
}

ce_wire::api! {
    api StateStore = "state.store", version 2, accepts [0x17de2d4fee4776ea];
    types {
        // Coll: one collection of one app. Every request also carries `cap`: the hex ce-cap chain that grants
        // `state.<app>.<coll>.read|write|own` (what `ce-iam wallet show state.store:<app>` prints). The Hello proves
        // which node calls; `cap` proves what that node may touch. An empty cap is refused.
        pub struct Coll { pub app: String, pub coll: String }
        // Doc: the stored record. value is JSON text; seq is the global write sequence (List/Watch cursor);
        // version counts writes of this key from 1; deleted marks a tombstone (Watch/include_deleted only).
        pub struct Doc { pub key: String, pub value: String, pub seq: u64, pub version: u64, pub deleted: bool }
        pub struct GetReq { pub at: Coll, pub key: String, pub cap: String }
        // PutReq: if_version = Some(v) is compare-and-set (refused unless the stored version is v; Some(0) means
        // "must not exist"); None replaces unconditionally. insert_only = create if absent, else return the stored doc.
        pub struct PutReq { pub at: Coll, pub key: String, pub value: String, pub if_version: Option<u64>, pub insert_only: bool, pub cap: String }
        // PatchReq: merge the top-level fields of `fields` (a JSON object) into the stored object.
        pub struct PatchReq { pub at: Coll, pub key: String, pub fields: String, pub cap: String }
        pub struct DeleteReq { pub at: Coll, pub key: String, pub cap: String }
        // ListReq: docs with seq > since whose key starts with prefix, in seq order, at most limit (<= MAX_PAGE).
        pub struct ListReq { pub at: Coll, pub prefix: String, pub since: u64, pub limit: u32, pub include_deleted: bool, pub cap: String }
        // Page: next = Some(cursor) when more remain; pass it as since.
        pub struct Page { pub docs: Vec<Doc>, pub next: Option<u64> }
        // WatchReq: every change (tombstones included) with seq > since, then each new one.
        pub struct WatchReq { pub at: Coll, pub since: u64, pub cap: String }
        pub struct SchemaReq { pub app: String, pub cap: String }
        // SchemaPutReq: schema is the JSON of {app, collections:{...}}; needs `state.<app>.admin`.
        pub struct SchemaPutReq { pub app: String, pub schema: String, pub cap: String }
        // PeerPull: one replication peer. last_ok_pull_at = unix ms of the last pull that applied cleanly, 0 = none
        // since this server started (held in memory); age_ms = now - last_ok_pull_at on this server's clock, u64::MAX
        // when none. A reader that needs a fresh replica (cap.admit: under 10 s) checks age_ms.
        pub struct PeerPull { pub peer: String, pub seq: u64, pub last_ok_pull_at: u64, pub age_ms: u64 }
        pub struct ReplStatus { pub node: String, pub peers: Vec<PeerPull> }
        pub struct StoreHealth { pub backend: String, pub records: u64, pub head_seq: u64, pub audit_rows: u64, pub schema_hash: u64 }
    }
    ops {
        1 => Get(GetReq) -> Option<Doc>, needs "state.store:read";
        2 => Put(PutReq) -> Doc, needs "state.store:write";
        3 => Delete(DeleteReq) -> (), needs "state.store:write";
        4 => List(ListReq) -> Page, needs "state.store:read";
        5 => Health(()) -> StoreHealth, needs "state.store:read";
        7 => Patch(PatchReq) -> Doc, needs "state.store:write";
        8 => Schema(SchemaReq) -> Option<String>, needs "state.store:read";
        9 => SchemaPut(SchemaPutReq) -> (), needs "state.store:write";
        10 => ReplHealth(()) -> ReplStatus, needs "state.store:read";
    }
    streams {
        6 => Watch(WatchReq) -> stream Doc, needs "state.store:read";
    }
}

/// Blocking typed client for one collection: `Docs::new(Client::<StateStore>::by_name(token)?, "huey-app", "calib", &cap)`.
/// `by_name` finds the cell through the door and starts it when it is not running. Live changes: use the async
/// `Client::subscribe::<Watch>` (see crates/state-store/src/main.rs for the pattern).
pub struct Docs {
    client: ce_wire::blocking::Client<StateStore>,
    at: Coll,
    cap: String,
}

impl Docs {
    /// `cap`: the hex grant, `ce-iam wallet show state.store:<app>@<node16>`.
    pub fn new(client: ce_wire::blocking::Client<StateStore>, app: &str, coll: &str, cap: &str) -> Self {
        Docs { client, at: Coll { app: app.into(), coll: coll.into() }, cap: cap.into() }
    }
    /// The value (JSON text) and version of `key`, or None.
    pub fn load(&self, key: &str) -> Result<Option<(String, u64)>, String> {
        let r = self.client.call::<Get>(&GetReq { at: self.at.clone(), key: key.into(), cap: self.cap.clone() }).map_err(|e| format!("{e:?}"))?;
        Ok(r.map(|d| (d.value, d.version)))
    }
    /// Write `value`. `expect` = Some(version from load) is compare-and-set; Some(0) = create only; None = replace.
    /// Returns the new version. Never retried here: a timed-out write may have landed.
    pub fn save(&self, key: &str, value: &str, expect: Option<u64>) -> Result<u64, String> {
        check_value(value)?;
        let d = self.client.call::<Put>(&PutReq { at: self.at.clone(), key: key.into(), value: value.into(), if_version: expect, insert_only: false, cap: self.cap.clone() }).map_err(|e| format!("{e:?}"))?;
        Ok(d.version)
    }
    pub fn remove(&self, key: &str) -> Result<(), String> {
        self.client.call::<Delete>(&DeleteReq { at: self.at.clone(), key: key.into(), cap: self.cap.clone() }).map_err(|e| format!("{e:?}"))
    }
    /// Docs under `prefix` after `since`, one page.
    pub fn list(&self, prefix: &str, since: u64) -> Result<Page, String> {
        self.client.call::<List>(&ListReq { at: self.at.clone(), prefix: prefix.into(), since, limit: MAX_PAGE, include_deleted: false, cap: self.cap.clone() }).map_err(|e| format!("{e:?}"))
    }
}
pub mod kv;
