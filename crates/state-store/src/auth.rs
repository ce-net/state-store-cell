//! ce-cap authorizer, the Rust form of python `CeIamAuthorizer`: a chain (hex, as `ce-iam wallet show` prints it)
//! authorizes `action` for `requester` on this node when it roots at this node's own key (each replica trusts only its
//! own key), is signed, unexpired, not revoked, and its leaf grants `action` to the requester. Fail closed.
use ce_gate::ce_cap::authorize;
use ce_gate::ce_identity::NodeId;
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::SystemTime;

pub struct Auth {
    me: NodeId,
    rev: Mutex<(Option<SystemTime>, HashSet<(NodeId, u64)>)>,
}

pub fn unhex32(s: &str) -> Option<NodeId> {
    if s.len() != 64 {
        return None;
    }
    let mut o = [0u8; 32];
    for i in 0..32 {
        o[i] = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(o)
}

fn ce_dir() -> std::path::PathBuf {
    ce_wire::ce_data_dir()
}

impl Auth {
    pub fn new(me: NodeId) -> Auth {
        Auth { me, rev: Mutex::new((None, HashSet::new())) }
    }

    fn revoked(&self, issuer: &NodeId, nonce: u64) -> bool {
        let path = ce_dir().join("revocations.json");
        let mut g = self.rev.lock().unwrap();
        let m = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        if m != g.0 {
            g.0 = m;
            g.1 = std::fs::read(&path)
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .and_then(|v| {
                    Some(
                        v.get("records")?
                            .as_array()?
                            .iter()
                            .filter_map(|r| {
                                let i: Vec<u8> = r.get("issuer")?.as_array()?.iter().filter_map(|x| x.as_u64().map(|x| x as u8)).collect();
                                Some((i.try_into().ok()?, r.get("nonce")?.as_u64()?))
                            })
                            .collect(),
                    )
                })
                .unwrap_or_default();
        }
        g.1.contains(&(*issuer, nonce))
    }

    pub fn ok(&self, cap: Option<&str>, action: &str, sender: &str) -> bool {
        let (Some(cap), Some(req)) = (cap.filter(|c| !c.is_empty()), unhex32(sender)) else { return false };
        let Ok(chain) = ce_gate::chain_from_hex(cap) else { return false };
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        authorize(&self.me, &[], &[], now, &req, action, &chain, &|i, n| self.revoked(i, n)).is_ok()
    }
}
