//! A few connections (Postgres hub: [`pg_conns`]; SQLite light replica: one) each behind a mutex, with the SQL dialect
//! differences hidden:
//! write `?` placeholders and `{TS}` for "now"; `V` is a column value. The schema is the python store's, byte for byte
//! (the two engines share one database during the migration).
use postgres::types::{to_sql_checked, IsNull, ToSql, Type};
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

#[derive(Clone, Debug)]
pub enum V {
    Null,
    I(i64),
    S(String),
    B(Vec<u8>),
    Bool(bool),
    J(Value),
}
impl V {
    pub fn i(&self) -> i64 {
        match self {
            V::I(i) => *i,
            V::Bool(b) => *b as i64,
            _ => 0,
        }
    }
    pub fn s(&self) -> String {
        match self {
            V::S(s) => s.clone(),
            _ => String::new(),
        }
    }
    pub fn b(&self) -> Option<Vec<u8>> {
        match self {
            V::B(b) => Some(b.clone()),
            _ => None,
        }
    }
    pub fn flag(&self) -> bool {
        self.i() != 0
    }
    pub fn json(&self) -> Value {
        match self {
            V::J(j) => j.clone(),
            V::S(s) => serde_json::from_str(s).unwrap_or(Value::Null),
            _ => Value::Null,
        }
    }
}
impl From<&str> for V {
    fn from(s: &str) -> V {
        V::S(s.into())
    }
}
impl From<String> for V {
    fn from(s: String) -> V {
        V::S(s)
    }
}
impl From<i64> for V {
    fn from(i: i64) -> V {
        V::I(i)
    }
}

impl ToSql for V {
    fn to_sql(&self, ty: &Type, out: &mut bytes::BytesMut) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        match self {
            V::Null => Ok(IsNull::Yes),
            V::I(i) => match *ty {
                Type::INT2 => (*i as i16).to_sql(ty, out),
                Type::INT4 => (*i as i32).to_sql(ty, out),
                _ => i.to_sql(ty, out),
            },
            V::S(s) => s.to_sql(ty, out),
            V::B(b) => b.to_sql(ty, out),
            V::Bool(b) => b.to_sql(ty, out),
            V::J(j) => j.to_sql(ty, out),
        }
    }
    fn accepts(_: &Type) -> bool {
        true
    }
    to_sql_checked!();
}

enum Conn {
    Pg(postgres::Client),
    Sqlite(rusqlite::Connection),
}

pub struct Db {
    /// One per concurrent caller: with a single connection, a burst from one caller (a cell re-inserting a 21k-row
    /// log after a restart) queued every typed call behind it and other cells timed out 55 times.
    c: Vec<Mutex<Conn>>,
    next: AtomicUsize,
    pub kind: &'static str,
    dsn: String,
}

pub struct Tx<'a> {
    c: &'a mut Conn,
}

const PG_DDL: &str = "
CREATE SEQUENCE IF NOT EXISTS write_seq;
CREATE TABLE IF NOT EXISTS records (
  app text NOT NULL, coll text NOT NULL, key text NOT NULL,
  seq bigint NOT NULL, version int NOT NULL, value bytea, deleted boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now(), updated_by text NOT NULL,
  PRIMARY KEY (app, coll, key));
ALTER TABLE records ADD COLUMN IF NOT EXISTS hlc text NOT NULL DEFAULT '';
ALTER TABLE records ADD COLUMN IF NOT EXISTS origin text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS records_seq ON records (app, coll, seq);
CREATE INDEX IF NOT EXISTS records_gseq ON records (seq);
CREATE TABLE IF NOT EXISTS audit (
  id bigserial PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(),
  app text NOT NULL, coll text NOT NULL, key text NOT NULL, op text NOT NULL,
  principal text NOT NULL, seq bigint NOT NULL, prev_hash text NOT NULL, hash text NOT NULL);
CREATE TABLE IF NOT EXISTS schemas (
  app text PRIMARY KEY, doc jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(), updated_by text NOT NULL);
ALTER TABLE schemas ADD COLUMN IF NOT EXISTS hlc text NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS repl_cursor (peer text PRIMARY KEY, seq bigint NOT NULL);
";

const SQLITE_DDL: &str = "
CREATE TABLE IF NOT EXISTS seqs (name TEXT PRIMARY KEY, n INTEGER NOT NULL);
INSERT OR IGNORE INTO seqs VALUES ('write', 0);
CREATE TABLE IF NOT EXISTS records (
  app TEXT NOT NULL, coll TEXT NOT NULL, key TEXT NOT NULL,
  seq INTEGER NOT NULL, version INTEGER NOT NULL, value BLOB, deleted INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL, updated_by TEXT NOT NULL, hlc TEXT NOT NULL DEFAULT '', origin TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (app, coll, key));
CREATE INDEX IF NOT EXISTS records_seq ON records (app, coll, seq);
CREATE INDEX IF NOT EXISTS records_gseq ON records (seq);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL,
  app TEXT NOT NULL, coll TEXT NOT NULL, key TEXT NOT NULL, op TEXT NOT NULL,
  principal TEXT NOT NULL, seq INTEGER NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS schemas (
  app TEXT PRIMARY KEY, doc TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL, hlc TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS repl_cursor (peer TEXT PRIMARY KEY, seq INTEGER NOT NULL);
";

fn dialect(sql: &str, pg: bool) -> String {
    if pg {
        let mut out = String::new();
        let mut n = 0;
        for ch in sql.replace("{TS}", "now()").chars() {
            if ch == '?' {
                n += 1;
                out.push_str(&format!("${n}"));
            } else {
                out.push(ch);
            }
        }
        out
    } else {
        sql.replace("{TS}", "strftime('%Y-%m-%dT%H:%M:%f','now')||'+00:00'").replace(" FOR UPDATE", "")
    }
}

/// The database could not be reached and nothing was written: clients may send the same call to another replica
/// (state-store-api StoreKv, the Python client's _NEXT / _NOT_WRITTEN). Keep the prefix exact.
pub const UNAVAILABLE: &str = "store unavailable: ";

fn unavailable(e: postgres::Error) -> String {
    format!("{UNAVAILABLE}{e}")
}

/// Postgres connections per server: `STATE_STORE_PG_CONNS`, default 4 (the python server ran ~10).
fn pg_conns() -> usize {
    std::env::var("STATE_STORE_PG_CONNS").ok().and_then(|v| v.trim().parse().ok()).filter(|n| *n > 0).unwrap_or(4)
}

impl Db {
    /// A free connection, or (all busy) a wait on the next one in turn.
    fn conn(&self) -> MutexGuard<'_, Conn> {
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        for i in 0..self.c.len() {
            if let Ok(g) = self.c[(start + i) % self.c.len()].try_lock() {
                return g;
            }
        }
        self.c[start % self.c.len()].lock().unwrap()
    }

    /// `sqlite:/path` or a Postgres DSN.
    pub fn open(url: &str) -> Result<Db, String> {
        if let Some(p) = url.strip_prefix("sqlite:") {
            let p = if let Some(r) = p.strip_prefix("~/") { format!("{}/{r}", std::env::var("HOME").unwrap_or_default()) } else { p.to_string() };
            if let Some(d) = std::path::Path::new(&p).parent() {
                let _ = std::fs::create_dir_all(d);
            }
            let fresh = !std::path::Path::new(&p).exists();
            let c = rusqlite::Connection::open(&p).map_err(|e| e.to_string())?;
            c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=30000;").map_err(|e| e.to_string())?;
            c.execute_batch(SQLITE_DDL).map_err(|e| e.to_string())?;
            if fresh {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
            }
            Ok(Db { c: vec![Mutex::new(Conn::Sqlite(c))], next: AtomicUsize::new(0), kind: "sqlite", dsn: String::new() })
        } else {
            let mut c = postgres::Client::connect(url, postgres::NoTls).map_err(|e| e.to_string())?;
            c.batch_execute(PG_DDL).map_err(|e| e.to_string())?;
            let mut cs = vec![Mutex::new(Conn::Pg(c))];
            for _ in 1..pg_conns() {
                cs.push(Mutex::new(Conn::Pg(postgres::Client::connect(url, postgres::NoTls).map_err(|e| e.to_string())?)));
            }
            Ok(Db { c: cs, next: AtomicUsize::new(0), kind: "postgres", dsn: url.into() })
        }
    }

    /// Run `f` on the connection (one statement or a read). A dropped Postgres connection is reopened once.
    /// Only reads come here (every write goes through `tx`), so a failed reopen is `store unavailable:`.
    pub fn q(&self, sql: &str, p: &[V]) -> Result<Vec<Vec<V>>, String> {
        let mut g = self.conn();
        run(&mut g, sql, p).or_else(|e| match &mut *g {
            Conn::Pg(c) if c.is_closed() => {
                *c = postgres::Client::connect(&self.dsn, postgres::NoTls).map_err(unavailable)?;
                run(&mut g, sql, p)
            }
            _ => Err(e),
        })
    }

    /// A transaction: `BEGIN` (SQLite: `BEGIN IMMEDIATE`, one writer), `COMMIT` when `f` returns Ok, else `ROLLBACK`.
    pub fn tx<T>(&self, f: impl FnOnce(&mut Tx) -> Result<T, String>) -> Result<T, String> {
        let mut g = self.conn();
        if let Conn::Pg(c) = &mut *g {
            if c.is_closed() {
                // before BEGIN: nothing of this transaction reached the database
                *c = postgres::Client::connect(&self.dsn, postgres::NoTls).map_err(unavailable)?;
            }
        }
        match &mut *g {
            Conn::Pg(c) => {
                c.batch_execute("BEGIN").map_err(|e| e.to_string())?;
                // one audit-chain writer at a time across processes (python takes the same key): no forks
                c.batch_execute("SELECT pg_advisory_xact_lock(7001)").map_err(|e| e.to_string())?;
            }
            Conn::Sqlite(c) => c.execute_batch("BEGIN IMMEDIATE").map_err(|e| e.to_string())?,
        }
        let r = f(&mut Tx { c: &mut g });
        let end = if r.is_ok() { "COMMIT" } else { "ROLLBACK" };
        let e = match &mut *g {
            Conn::Pg(c) => c.batch_execute(end).map_err(|e| e.to_string()),
            Conn::Sqlite(c) => c.execute_batch(end).map_err(|e| e.to_string()),
        };
        let v = r?;
        e?;
        Ok(v)
    }
}

impl Tx<'_> {
    pub fn q(&mut self, sql: &str, p: &[V]) -> Result<Vec<Vec<V>>, String> {
        run(self.c, sql, p)
    }
    pub fn nextseq(&mut self) -> Result<i64, String> {
        let sql = match self.c {
            Conn::Pg(_) => "SELECT nextval('write_seq')",
            Conn::Sqlite(_) => "UPDATE seqs SET n=n+1 WHERE name='write' RETURNING n",
        };
        Ok(self.q(sql, &[])?[0][0].i())
    }
}

fn run(c: &mut Conn, sql: &str, p: &[V]) -> Result<Vec<Vec<V>>, String> {
    match c {
        Conn::Pg(c) => {
            let sql = dialect(sql, true);
            let params: Vec<&(dyn ToSql + Sync)> = p.iter().map(|v| v as &(dyn ToSql + Sync)).collect();
            if p.is_empty() && sql.matches(';').count() > 0 && !sql.to_uppercase().starts_with("SELECT") {
                c.batch_execute(&sql).map_err(|e| e.to_string())?;
                return Ok(vec![]);
            }
            let rows = c.query(&sql, &params).map_err(|e| e.to_string())?;
            Ok(rows
                .iter()
                .map(|r| {
                    (0..r.len())
                        .map(|i| {
                            let t = r.columns()[i].type_().clone();
                            match t {
                                Type::INT8 => r.get::<_, Option<i64>>(i).map_or(V::Null, V::I),
                                Type::INT4 => r.get::<_, Option<i32>>(i).map_or(V::Null, |v| V::I(v as i64)),
                                Type::INT2 => r.get::<_, Option<i16>>(i).map_or(V::Null, |v| V::I(v as i64)),
                                Type::BOOL => r.get::<_, Option<bool>>(i).map_or(V::Null, V::Bool),
                                Type::BYTEA => r.get::<_, Option<Vec<u8>>>(i).map_or(V::Null, V::B),
                                Type::JSONB | Type::JSON => r.get::<_, Option<Value>>(i).map_or(V::Null, V::J),
                                _ => r.get::<_, Option<String>>(i).map_or(V::Null, V::S),
                            }
                        })
                        .collect()
                })
                .collect())
        }
        Conn::Sqlite(c) => {
            let sql = dialect(sql, false);
            let mut st = c.prepare(&sql).map_err(|e| e.to_string())?;
            let n = st.column_count();
            let params: Vec<rusqlite::types::Value> = p
                .iter()
                .map(|v| match v {
                    V::Null => rusqlite::types::Value::Null,
                    V::I(i) => rusqlite::types::Value::Integer(*i),
                    V::S(s) => rusqlite::types::Value::Text(s.clone()),
                    V::B(b) => rusqlite::types::Value::Blob(b.clone()),
                    V::Bool(b) => rusqlite::types::Value::Integer(*b as i64),
                    V::J(j) => rusqlite::types::Value::Text(j.to_string()),
                })
                .collect();
            let mut rows = st.query(rusqlite::params_from_iter(params)).map_err(|e| e.to_string())?;
            let mut out = vec![];
            while let Some(r) = rows.next().map_err(|e| e.to_string())? {
                out.push(
                    (0..n)
                        .map(|i| match r.get_ref_unwrap(i) {
                            rusqlite::types::ValueRef::Null => V::Null,
                            rusqlite::types::ValueRef::Integer(i) => V::I(i),
                            rusqlite::types::ValueRef::Real(f) => V::I(f as i64),
                            rusqlite::types::ValueRef::Text(t) => V::S(String::from_utf8_lossy(t).into()),
                            rusqlite::types::ValueRef::Blob(b) => V::B(b.to_vec()),
                        })
                        .collect(),
                );
            }
            Ok(out)
        }
    }
}

/// The DDL batch for a statement without parameters is run through `q` as well (DDL runs at open).
#[allow(dead_code)]
pub fn dialect_for_test(sql: &str, pg: bool) -> String {
    dialect(sql, pg)
}
