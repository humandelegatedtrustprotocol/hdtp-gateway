//! The limits sidecar's protocol and store: everything `hdtp-limitd` does apart from owning a
//! socket, as pure functions over a [`Store`], so it is tested without one.
//!
//! The node asks over a kept-open unix socket, one JSON object a line (the owner's decision of
//! 2026-09-29, `docs/release/two-layer-limits-2026-09-28.md` §6: the node opens the envelope and asks
//! the sidecar, sending the charge; no key leaves the node). Every request names the identity the
//! call was addressed to, and every bucket is that identity's: one process serves every account on
//! the node, and one account's contacts never spend another's.
//!
//! ```text
//! {"op":"decide","identity":"acc-1","charges":[{"kind":"contact_in","root":"sha256:…","contact_cap":500}],"known":"203.0.113.9","now":1790000000123}
//! {"allowed":true,"retry_after":0,"refused_by":null}
//! {"op":"admit","identity":"acc-1","source":"198.51.100.4","now":1790000000123}
//! {"allowed":false,"retry_after":412,"refused_by":"guest-total"}
//! {"op":"rules"}
//! {"rules":{"contact_calls_per_second":1,…}}
//! {"op":"card","contact_cap":500}
//! {"limits":{"contact_calls_per_second":1,"contact_burst":10,"identity_calls_per_second":200,…}}
//! {"op":"nonsense"}
//! {"error":"op is one of decide, admit, rules, card"}
//! ```
//!
//! `decide` charges one call to every one of `charges`, in order, all or none: a guest's call after
//! the open is its guest buckets and the identity's guest total (`guest_total`). `known`, when the
//! node sends it, is the source of a call the open proved an active or pending contact's: it is
//! remembered for the identity, whatever the budgets answer, for [`KNOWN_SOURCE_TTL_MS`].
//!
//! `admit` is the check BEFORE the open (the owner's decision of 2026-09-29 on the guest total): a
//! sealed call from `source` may go on to the open when the source is known, or while the
//! identity's guest total has a call left; it spends nothing, and the refusal is the total's. No
//! source is ever known.
//!
//! `card` is what `get_card` advertises of the call budgets (HDTP §12's `limits` members about
//! calls) for an identity allowed `contact_cap` contacts: the rules' numbers, and the identity's
//! aggregate as the crate computes it (`Rules::identity_per_second`), so the node holds no copy of
//! that formula.
//!
//! The charge is the contract's `LimitsCharge` (hdtp-identity CONTRACT §6.3), read as the Go port
//! reads it; the answer is the contract's `limits_decide` result without its `writes`, which are
//! the sidecar's own.

use hdtp_limits::{decide, Charge, Decision, Level, Rules, StateStore, IDLE_MS, RULE_MEMBERS};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::HashMap;

/// How long a source stays known after the last proven contact's call it carried.
pub const KNOWN_SOURCE_TTL_MS: i64 = 3_600_000;

/// The most sources one identity remembers; past it the oldest goes.
pub const KNOWN_SOURCES_CAP: usize = 4096;

/// The configuration file: where to listen, and the rules.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub socket: String,
    pub rules: Rules,
    /// The rules as the file wrote them, answered to `rules` verbatim (numbers as written).
    pub rules_doc: Map<String, Value>,
}

/// Reads a configuration document: `socket` (a path) and `rules` (the contract's `LimitsRules`,
/// held to `Rules::check`). The first reason it cannot be used is the error.
pub fn read_config(text: &str) -> Result<Config, String> {
    let doc: Value = serde_json::from_str(text).map_err(|e| format!("the configuration does not read as JSON: {e}"))?;
    let obj = doc.as_object().ok_or("the configuration is an object")?;
    for k in obj.keys() {
        if k != "socket" && k != "rules" {
            return Err(format!("the configuration holds socket and rules, and nothing else: {k}"));
        }
    }
    let socket = obj.get("socket").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("socket is a path")?.to_string();
    let rules_doc = obj.get("rules").and_then(Value::as_object).ok_or("the limits rules are an object")?.clone();
    let rules = read_rules(&rules_doc)?;
    Ok(Config { socket, rules, rules_doc })
}

/// A rules document, as `limits_rules_check` reads one: every member named, each a number,
/// nothing else, and enforceable.
pub fn read_rules(doc: &Map<String, Value>) -> Result<Rules, String> {
    let mut names: Vec<&String> = doc.keys().collect();
    names.sort();
    for k in names {
        if !RULE_MEMBERS.contains(&k.as_str()) {
            return Err(format!("the limits rules hold {}, and nothing else: {k}", RULE_MEMBERS.join(", ")));
        }
    }
    for m in RULE_MEMBERS {
        if !doc.get(m).map(Value::is_number).unwrap_or(false) {
            return Err(format!("{m} is a number"));
        }
    }
    let rules = Rules::from_members(|name| doc.get(name).and_then(Value::as_f64).unwrap_or(f64::NAN));
    rules.check()?;
    Ok(rules)
}

/// The counters: every identity's rows in one map, keyed by the identity and the bucket. A row
/// idle for [`IDLE_MS`] is full whatever it budgets (`Rules::check` holds every bucket to that),
/// so the sweep deletes it, at most once a minute.
#[derive(Debug, Default)]
pub struct Store {
    rows: HashMap<String, Level>,
    /// Per identity, the sources a proven contact's call came from, and when it last did.
    known: HashMap<String, HashMap<String, i64>>,
    last_sweep: i64,
}

/// How often idle rows are dropped.
pub const SWEEP_EVERY_MS: i64 = 60_000;

impl Store {
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// How many sources `identity` remembers.
    pub fn known_len(&self, identity: &str) -> usize {
        self.known.get(identity).map_or(0, HashMap::len)
    }

    fn sweep(&mut self, now: i64) {
        if now - self.last_sweep < SWEEP_EVERY_MS {
            return;
        }
        self.last_sweep = now;
        self.rows.retain(|_, l| l.updated_at >= now - IDLE_MS);
        for sources in self.known.values_mut() {
            sources.retain(|_, seen| *seen >= now - KNOWN_SOURCE_TTL_MS);
        }
        self.known.retain(|_, sources| !sources.is_empty());
    }

    /// Remembers that `source` carried a proven contact's call to `identity` at `now`; past the cap,
    /// the source seen longest ago goes. No source is never remembered.
    fn remember(&mut self, identity: &str, source: &str, now: i64) {
        if source.is_empty() {
            return;
        }
        let sources = self.known.entry(identity.to_string()).or_default();
        let seen = sources.entry(source.to_string()).or_insert(now);
        *seen = (*seen).max(now);
        if sources.len() > KNOWN_SOURCES_CAP {
            let oldest = sources.iter().min_by(|a, b| a.1.cmp(b.1).then_with(|| a.0.cmp(b.0))).map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                sources.remove(&k);
            }
        }
    }

    /// Whether `source` carried a proven contact's call to `identity` within the last
    /// [`KNOWN_SOURCE_TTL_MS`]. No source is never known.
    fn knows(&self, identity: &str, source: &str, now: i64) -> bool {
        !source.is_empty() && self.known.get(identity).and_then(|s| s.get(source)).is_some_and(|seen| *seen >= now - KNOWN_SOURCE_TTL_MS)
    }
}

fn row_key(identity: &str, bucket: &str) -> String {
    format!("{identity}\u{0}{bucket}")
}

/// One identity's view of the store, with its writes held back: the crate sees bucket keys and
/// reads what the charges before it wrote, and nothing reaches the store until [`Overlay::commit`].
struct Overlay<'a> {
    store: &'a Store,
    identity: &'a str,
    writes: HashMap<String, Level>,
}

impl Overlay<'_> {
    fn into_writes(self) -> Vec<(String, Level)> {
        let identity = self.identity;
        self.writes.into_iter().map(|(k, l)| (row_key(identity, &k), l)).collect()
    }
}

impl StateStore for Overlay<'_> {
    fn get(&self, key: &str) -> Option<Level> {
        self.writes.get(key).copied().or_else(|| self.store.rows.get(&row_key(self.identity, key)).copied())
    }
    fn put(&mut self, key: &str, level: Level) {
        self.writes.insert(key.to_string(), level);
    }
}

/// Decides `charges` for `identity` over the store as it stands, in order: the first refusal is the
/// answer, and the writes of an allowed set, which the caller commits or drops.
fn decide_all(rules: &Rules, store: &Store, identity: &str, charges: &[Charge], now: i64) -> (Answer, Vec<(String, Level)>) {
    let mut overlay = Overlay { store, identity, writes: HashMap::new() };
    for charge in charges {
        if let Decision::Refuse { retry_after, which } = decide(rules, charge, now, &mut overlay) {
            return (Answer { allowed: false, retry_after, refused_by: Some(which) }, Vec::new());
        }
    }
    (Answer { allowed: true, retry_after: Some(0), refused_by: None }, overlay.into_writes())
}

/// The answer to `decide` and `admit`: the contract's `limits_decide` result without `writes`.
#[derive(Debug, Serialize, PartialEq)]
pub struct Answer {
    pub allowed: bool,
    pub retry_after: Option<u64>,
    pub refused_by: Option<String>,
}

fn read_charges(v: Option<&Value>) -> Result<Vec<Charge>, String> {
    let list = v.and_then(Value::as_array).filter(|l| !l.is_empty()).ok_or("charges is a list of one or more charges")?;
    list.iter().map(read_charge).collect()
}

fn read_charge(v: &Value) -> Result<Charge, String> {
    let o = v.as_object().ok_or("a charge is an object")?;
    let kind = o.get("kind").and_then(Value::as_str).ok_or("charge.kind is required")?;
    let members: &[&str] = match kind {
        "contact_in" | "contact_out" => &["kind", "root", "contact_cap"],
        "guest_in" => &["kind", "root", "source", "addressed"],
        "guest_total" | "stranger_out" => &["kind"],
        "integration" => &["kind", "integration", "contact"],
        "pending_in" => &["kind", "held"],
        _ => {
            return Err("charge.kind is one of contact_in, guest_in, guest_total, contact_out, stranger_out, integration, pending_in".into())
        }
    };
    let mut names: Vec<&String> = o.keys().collect();
    names.sort();
    for k in names {
        if !members.contains(&k.as_str()) {
            return Err(format!("a {kind} charge holds {}, and nothing else: {k}", members.join(", ")));
        }
    }
    let text = |m: &str| -> Result<String, String> {
        match o.get(m).and_then(Value::as_str) {
            Some(s) if !s.is_empty() => Ok(s.to_string()),
            _ => Err(format!("charge.{m} is required")),
        }
    };
    let count = |m: &str| -> Result<f64, String> {
        match o.get(m).and_then(Value::as_u64) {
            Some(n) if n <= 9_007_199_254_740_991 => Ok(n as f64),
            _ => Err(format!("charge.{m} is a whole number")),
        }
    };
    Ok(match kind {
        "contact_in" => Charge::ContactIn { root: text("root")?, contact_cap: count("contact_cap")? },
        "contact_out" => Charge::ContactOut { root: text("root")?, contact_cap: count("contact_cap")? },
        "guest_in" => {
            let root = match o.get("root") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) => Some(s.clone()),
                Some(_) => return Err("charge.root is a string or null".into()),
            };
            let source = o.get("source").and_then(Value::as_str).ok_or("charge.source is required")?.to_string();
            let addressed = o.get("addressed").and_then(Value::as_bool).ok_or("charge.addressed is required")?;
            Charge::GuestIn { root, source, addressed }
        }
        "guest_total" => Charge::GuestTotal,
        "stranger_out" => Charge::StrangerOut,
        "integration" => Charge::Integration { integration: text("integration")?, contact: text("contact")? },
        _ => Charge::PendingIn { held: count("held")? },
    })
}

/// Answers one request line. Every answer is one line of JSON; a request that does not read is
/// `{"error":…}` and changes nothing.
pub fn handle(rules: &Rules, rules_doc: &Map<String, Value>, store: &mut Store, line: &str) -> String {
    match handle_inner(rules, rules_doc, store, line) {
        Ok(v) => v.to_string(),
        Err(why) => serde_json::json!({ "error": why }).to_string(),
    }
}

fn handle_inner(rules: &Rules, rules_doc: &Map<String, Value>, store: &mut Store, line: &str) -> Result<Value, String> {
    let req: Value = serde_json::from_str(line).map_err(|_| "a request is one JSON object a line".to_string())?;
    let o = req.as_object().ok_or("a request is a JSON object")?;
    let op = o.get("op").and_then(Value::as_str).ok_or("op is required")?;
    match op {
        "decide" | "admit" => {}
        "rules" => return Ok(serde_json::json!({ "rules": Value::Object(rules_doc.clone()) })),
        "card" => {
            let cap = o
                .get("contact_cap")
                .and_then(Value::as_u64)
                .filter(|n| *n <= 9_007_199_254_740_991)
                .ok_or("contact_cap is a whole number")?;
            let member = |m: &str| rules_doc.get(m).cloned().unwrap_or(Value::Null);
            return Ok(serde_json::json!({ "limits": {
                "contact_calls_per_second": member("contact_calls_per_second"),
                "contact_burst": member("contact_burst"),
                "identity_calls_per_second": rules.identity_per_second(cap as f64),
                "guest_calls_per_hour": member("guest_calls_per_hour"),
                "guest_source_calls_per_hour": member("guest_source_calls_per_hour"),
            } }));
        }
        _ => return Err("op is one of decide, admit, rules, card".into()),
    }
    let identity = o.get("identity").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("identity is required")?;
    let now = o.get("now").and_then(Value::as_i64).filter(|n| *n >= 0).ok_or("now is a time in milliseconds")?;
    let answer = if op == "admit" {
        let source = o.get("source").and_then(Value::as_str).ok_or("source is a string")?;
        store.sweep(now);
        if store.knows(identity, source, now) {
            Answer { allowed: true, retry_after: Some(0), refused_by: None }
        } else {
            // The guest total, asked and not spent: the writes of the decision are dropped.
            decide_all(rules, store, identity, &[Charge::GuestTotal], now).0
        }
    } else {
        let charges = read_charges(o.get("charges"))?;
        let known = match o.get("known") {
            None => None,
            Some(Value::String(k)) => Some(k.as_str()),
            Some(_) => return Err("known is a string".into()),
        };
        store.sweep(now);
        if let Some(k) = known {
            store.remember(identity, k, now);
        }
        let (answer, writes) = decide_all(rules, store, identity, &charges, now);
        store.rows.extend(writes);
        answer
    };
    Ok(serde_json::to_value(answer).expect("an answer serialises"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"{"socket":"/tmp/x.sock","rules":{"contact_calls_per_second":1,"contact_burst":10,"identity_capacity_per_second":200,"guest_calls_per_hour":10,"guest_source_calls_per_hour":60,"stranger_calls_out_per_hour":20,"integration_calls_per_hour":60,"guest_total_calls_per_hour":600,"pending_in_cap":500}}"#;

    fn cfg() -> Config {
        read_config(DOC).unwrap()
    }

    fn ask(c: &Config, s: &mut Store, line: &str) -> Value {
        serde_json::from_str(&handle(&c.rules, &c.rules_doc, s, line)).unwrap()
    }

    #[test]
    fn a_configuration_is_its_socket_and_enforceable_rules() {
        let c = cfg();
        assert_eq!(c.socket, "/tmp/x.sock");
        assert_eq!(c.rules.guest_total_calls_per_hour, 600.0);
        assert_eq!(c.rules.pending_in_cap, 500.0);
        for (text, why) in [
            ("[]", "the configuration is an object"),
            (r#"{"socket":"/s","rules":{},"extra":1}"#, "the configuration holds socket and rules, and nothing else: extra"),
            (r#"{"rules":{}}"#, "socket is a path"),
            (r#"{"socket":"/s"}"#, "the limits rules are an object"),
            (r#"{"socket":"/s","rules":{"zeta":1}}"#, "the limits rules hold contact_calls_per_second, contact_burst, identity_capacity_per_second, guest_calls_per_hour, guest_source_calls_per_hour, stranger_calls_out_per_hour, integration_calls_per_hour, guest_total_calls_per_hour, pending_in_cap, and nothing else: zeta"),
            (&DOC.replace(r#""pending_in_cap":500"#, r#""pending_in_cap":"500""#), "pending_in_cap is a number"),
            (&DOC.replace(r#""guest_total_calls_per_hour":600"#, r#""guest_total_calls_per_hour":0"#), "guest_total_calls_per_hour is at least 1"),
            (&DOC.replace(r#""pending_in_cap":500"#, r#""pending_in_cap":1.5"#), "pending_in_cap is a whole number"),
        ] {
            assert_eq!(read_config(text).unwrap_err(), why, "{text}");
        }
    }

    #[test]
    fn a_fresh_identity_is_let_through_on_every_kind_of_charge_and_every_budget_refuses_once_spent() {
        let c = cfg();
        let mut s = Store::default();
        let now = 1_790_000_000_000i64;
        let charges = [
            (r#"{"kind":"contact_in","root":"sha256:A","contact_cap":500}"#, 10, "contact:sha256:A"),
            (r#"{"kind":"guest_in","root":"sha256:G","source":"203.0.113.9","addressed":true}"#, 10, "guest:sha256:G:203.0.113.9"),
            (r#"{"kind":"guest_in","root":null,"source":"203.0.113.9","addressed":true}"#, 60, "source:203.0.113.9"),
            (r#"{"kind":"guest_total"}"#, 600, "guest-total"),
            (r#"{"kind":"contact_out","root":"sha256:A","contact_cap":500}"#, 10, "out:contact:sha256:A"),
            (r#"{"kind":"stranger_out"}"#, 20, "out:stranger"),
            (r#"{"kind":"integration","integration":"i1","contact":"sha256:A"}"#, 60, "integration:i1:sha256:A"),
        ];
        for (charge, burst, bucket) in charges {
            for i in 0..burst {
                let a = ask(&c, &mut s, &format!(r#"{{"op":"decide","identity":"acc-1","charges":[{charge}],"now":{now}}}"#));
                assert_eq!(a["allowed"], true, "{charge} call {}", i + 1);
            }
            let a = ask(&c, &mut s, &format!(r#"{{"op":"decide","identity":"acc-1","charges":[{charge}],"now":{now}}}"#));
            assert_eq!(a["allowed"], false, "{charge} past its burst");
            assert_eq!(a["refused_by"], bucket);
            assert!(a["retry_after"].as_u64().unwrap() >= 1);
            // Another identity's same bucket is untouched: the counter is per identity.
            let b = ask(&c, &mut s, &format!(r#"{{"op":"decide","identity":"acc-2","charges":[{charge}],"now":{now}}}"#));
            assert_eq!(b["allowed"], true, "{charge} for another identity");
        }
        // The pending cap is a count, refused with no wait.
        let a =
            ask(&c, &mut s, &format!(r#"{{"op":"decide","identity":"acc-1","charges":[{{"kind":"pending_in","held":499}}],"now":{now}}}"#));
        assert_eq!(a["allowed"], true);
        let a =
            ask(&c, &mut s, &format!(r#"{{"op":"decide","identity":"acc-1","charges":[{{"kind":"pending_in","held":500}}],"now":{now}}}"#));
        assert_eq!(a, serde_json::json!({ "allowed": false, "retry_after": null, "refused_by": "pending_in" }));
    }

    #[test]
    fn idle_rows_are_swept_and_nothing_a_caller_sees_changes() {
        let c = cfg();
        let mut s = Store::default();
        let now = 1_790_000_000_000i64;
        for i in 0..50 {
            ask(
                &c,
                &mut s,
                &format!(
                    r#"{{"op":"decide","identity":"acc-1","charges":[{{"kind":"guest_in","root":"sha256:r{i}","source":"s","addressed":true}}],"now":{now}}}"#
                ),
            );
        }
        assert_eq!(s.len(), 50);
        // An hour and a minute later the first decision sweeps them all; a call then is let through
        // exactly as a call against a full row would be.
        let later = now + IDLE_MS + SWEEP_EVERY_MS;
        let a = ask(
            &c,
            &mut s,
            &format!(
                r#"{{"op":"decide","identity":"acc-1","charges":[{{"kind":"guest_in","root":"sha256:r0","source":"s","addressed":true}}],"now":{later}}}"#
            ),
        );
        assert_eq!(a["allowed"], true);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn the_card_advertises_the_rules_and_the_crates_aggregate() {
        let c = cfg();
        let mut s = Store::default();
        let card = |cap: u64, s: &mut Store| ask(&c, s, &format!(r#"{{"op":"card","contact_cap":{cap}}}"#))["limits"].clone();
        let got = card(500, &mut s);
        assert_eq!(got["contact_calls_per_second"], 1);
        assert_eq!(got["contact_burst"], 10);
        assert_eq!(got["guest_calls_per_hour"], 10);
        assert_eq!(got["guest_source_calls_per_hour"], 60);
        // 500 contacts at one a second ask for 500; this configuration's capacity is 200.
        assert_eq!(got["identity_calls_per_second"].as_f64(), Some(c.rules.identity_per_second(500.0)));
        assert_eq!(got["identity_calls_per_second"].as_f64(), Some(200.0));
        assert_eq!(card(7, &mut s)["identity_calls_per_second"].as_f64(), Some(7.0));
        // Never below one call a second, whatever the cap.
        assert_eq!(card(0, &mut s)["identity_calls_per_second"].as_f64(), Some(1.0));
        assert!(s.is_empty(), "the card wrote a row");
    }

    #[test]
    fn the_rules_are_answered_as_written_and_a_request_that_does_not_read_changes_nothing() {
        let c = cfg();
        let mut s = Store::default();
        let r = ask(&c, &mut s, r#"{"op":"rules"}"#);
        assert_eq!(r["rules"]["guest_total_calls_per_hour"], 600);
        assert_eq!(r["rules"].as_object().unwrap().len(), 9);
        for (line, why) in [
            ("nope", "a request is one JSON object a line"),
            ("[1]", "a request is a JSON object"),
            (r#"{"charges":[]}"#, "op is required"),
            (r#"{"op":"sweep"}"#, "op is one of decide, admit, rules, card"),
            (r#"{"op":"check"}"#, "op is one of decide, admit, rules, card"),
            (r#"{"op":"card"}"#, "contact_cap is a whole number"),
            (r#"{"op":"card","contact_cap":-1}"#, "contact_cap is a whole number"),
            (r#"{"op":"decide","charges":[{"kind":"guest_total"}],"now":1}"#, "identity is required"),
            (r#"{"op":"decide","identity":"a","charges":[{"kind":"guest_total"}]}"#, "now is a time in milliseconds"),
            (r#"{"op":"decide","identity":"a","charges":[{"kind":"guest_total"}],"now":-1}"#, "now is a time in milliseconds"),
            (r#"{"op":"decide","identity":"a","now":1}"#, "charges is a list of one or more charges"),
            (r#"{"op":"decide","identity":"a","charges":[],"now":1}"#, "charges is a list of one or more charges"),
            (r#"{"op":"decide","identity":"a","charges":{"kind":"guest_total"},"now":1}"#, "charges is a list of one or more charges"),
            (r#"{"op":"decide","identity":"a","charges":[1],"now":1}"#, "a charge is an object"),
            (r#"{"op":"decide","identity":"a","charges":[{"kind":"guest_total"}],"known":7,"now":1}"#, "known is a string"),
            (r#"{"op":"admit","identity":"a","now":1}"#, "source is a string"),
            (r#"{"op":"admit","source":"s","now":1}"#, "identity is required"),
            (
                r#"{"op":"decide","identity":"a","charges":[{"kind":"tea"}],"now":1}"#,
                "charge.kind is one of contact_in, guest_in, guest_total, contact_out, stranger_out, integration, pending_in",
            ),
            (
                r#"{"op":"decide","identity":"a","charges":[{"kind":"contact_in","root":"x","contact_cap":1,"extra":1}],"now":1}"#,
                "a contact_in charge holds kind, root, contact_cap, and nothing else: extra",
            ),
            (
                r#"{"op":"decide","identity":"a","charges":[{"kind":"contact_in","root":"","contact_cap":1}],"now":1}"#,
                "charge.root is required",
            ),
            (
                r#"{"op":"decide","identity":"a","charges":[{"kind":"contact_in","root":"x","contact_cap":1.5}],"now":1}"#,
                "charge.contact_cap is a whole number",
            ),
            (
                r#"{"op":"decide","identity":"a","charges":[{"kind":"guest_in","root":5,"source":"s","addressed":true}],"now":1}"#,
                "charge.root is a string or null",
            ),
            (r#"{"op":"decide","identity":"a","charges":[{"kind":"guest_in","source":"s"}],"now":1}"#, "charge.addressed is required"),
            (r#"{"op":"decide","identity":"a","charges":[{"kind":"pending_in"}],"now":1}"#, "charge.held is a whole number"),
            // One bad charge of several refuses the request, and the good ones before it spend nothing.
            (
                r#"{"op":"decide","identity":"a","charges":[{"kind":"guest_total"},{"kind":"tea"}],"now":1}"#,
                "charge.kind is one of contact_in, guest_in, guest_total, contact_out, stranger_out, integration, pending_in",
            ),
        ] {
            assert_eq!(ask(&c, &mut s, line), serde_json::json!({ "error": why }), "{line}");
        }
        assert!(s.is_empty());
        assert_eq!(s.known_len("a"), 0);
    }

    const NOW: i64 = 1_790_000_000_000;

    fn spend_total(c: &Config, s: &mut Store, identity: &str) {
        for i in 0..c.rules.guest_total_calls_per_hour as u64 {
            let a = ask(c, s, &format!(r#"{{"op":"decide","identity":"{identity}","charges":[{{"kind":"guest_total"}}],"now":{NOW}}}"#));
            assert_eq!(a["allowed"], true, "total call {}", i + 1);
        }
    }

    #[test]
    fn several_charges_are_spent_together_or_not_at_all() {
        let c = cfg();
        let mut s = Store::default();
        spend_total(&c, &mut s, "acc-1");
        let rows = s.len();
        let a = ask(
            &c,
            &mut s,
            &format!(
                r#"{{"op":"decide","identity":"acc-1","charges":[{{"kind":"guest_in","root":"sha256:G","source":"s","addressed":true}},{{"kind":"guest_total"}}],"now":{NOW}}}"#
            ),
        );
        assert_eq!(a["allowed"], false);
        assert_eq!(a["refused_by"], "guest-total");
        assert!(a["retry_after"].as_u64().unwrap() >= 1);
        assert_eq!(s.len(), rows, "the guest bucket of a call the total refused was written");
        // Both allowed: both written.
        let a = ask(
            &c,
            &mut s,
            &format!(
                r#"{{"op":"decide","identity":"acc-2","charges":[{{"kind":"guest_in","root":"sha256:G","source":"s","addressed":true}},{{"kind":"guest_total"}}],"now":{NOW}}}"#
            ),
        );
        assert_eq!(a["allowed"], true);
        assert_eq!(s.len(), rows + 2);
    }

    #[test]
    fn admit_lets_a_call_to_the_open_while_the_total_holds_one_or_from_a_known_source_and_spends_nothing() {
        let c = cfg();
        let mut s = Store::default();
        let admit = |s: &mut Store, identity: &str, source: &str, now: i64| {
            ask(&c, s, &format!(r#"{{"op":"admit","identity":"{identity}","source":"{source}","now":{now}}}"#))
        };
        // A fresh identity: let through, and nothing written.
        assert_eq!(
            admit(&mut s, "acc-1", "203.0.113.1", NOW),
            serde_json::json!({ "allowed": true, "retry_after": 0, "refused_by": null })
        );
        assert!(s.is_empty(), "admit wrote a row");
        // A contact's call proves its source, whatever the budgets answer.
        ask(
            &c,
            &mut s,
            &format!(
                r#"{{"op":"decide","identity":"acc-1","charges":[{{"kind":"contact_in","root":"sha256:C","contact_cap":500}}],"known":"198.51.100.1","now":{NOW}}}"#
            ),
        );
        spend_total(&c, &mut s, "acc-1");
        let rows = s.len();
        // Spent: an unknown source is refused, with the total's wait and name, and nothing written.
        let refused = admit(&mut s, "acc-1", "203.0.113.2", NOW);
        assert_eq!(refused["allowed"], false);
        assert_eq!(refused["refused_by"], "guest-total");
        assert!(refused["retry_after"].as_u64().unwrap() >= 1);
        assert_eq!(s.len(), rows);
        // The known source is let through, for this identity alone, and for the hour.
        assert_eq!(admit(&mut s, "acc-1", "198.51.100.1", NOW)["allowed"], true);
        spend_total(&c, &mut s, "acc-2");
        assert_eq!(admit(&mut s, "acc-2", "198.51.100.1", NOW)["allowed"], false, "known to another identity");
        assert_eq!(admit(&mut s, "acc-1", "198.51.100.1", NOW + KNOWN_SOURCE_TTL_MS - 1)["allowed"], true);
        // Past the hour it is forgotten; by then the total has refilled too, so ask with it spent again.
        let later = NOW + KNOWN_SOURCE_TTL_MS + SWEEP_EVERY_MS;
        for _ in 0..c.rules.guest_total_calls_per_hour as u64 {
            ask(&c, &mut s, &format!(r#"{{"op":"decide","identity":"acc-1","charges":[{{"kind":"guest_total"}}],"now":{later}}}"#));
        }
        assert_eq!(admit(&mut s, "acc-1", "198.51.100.1", later)["allowed"], false, "known past the hour");
        assert_eq!(s.known_len("acc-1"), 0, "the sweep kept an expired source");
    }

    #[test]
    fn no_source_is_ever_known_and_the_cap_forgets_the_oldest() {
        let c = cfg();
        let mut s = Store::default();
        ask(&c, &mut s, &format!(r#"{{"op":"decide","identity":"acc-1","charges":[{{"kind":"stranger_out"}}],"known":"","now":{NOW}}}"#));
        assert_eq!(s.known_len("acc-1"), 0, "no source was remembered");
        spend_total(&c, &mut s, "acc-1");
        assert_eq!(ask(&c, &mut s, &format!(r#"{{"op":"admit","identity":"acc-1","source":"","now":{NOW}}}"#))["allowed"], false);
        // A row for no source, however it came to be, makes no source known.
        s.known.entry("acc-2".into()).or_default().insert(String::new(), NOW);
        assert!(!s.knows("acc-2", "", NOW));
        // And a source past the hour is not known, whether or not a sweep has run since.
        s.remember("acc-3", "src-old", NOW);
        assert!(s.knows("acc-3", "src-old", NOW + KNOWN_SOURCE_TTL_MS));
        assert!(!s.knows("acc-3", "src-old", NOW + KNOWN_SOURCE_TTL_MS + 1));
        for i in 0..KNOWN_SOURCES_CAP + 3 {
            s.remember("acc-1", &format!("src-{i}"), NOW + i as i64);
        }
        assert_eq!(s.known_len("acc-1"), KNOWN_SOURCES_CAP);
        let now = NOW + KNOWN_SOURCES_CAP as i64 + 3;
        for i in 0..3 {
            assert!(!s.knows("acc-1", &format!("src-{i}"), now), "src-{i}, among the oldest, is still known");
        }
        assert!(s.knows("acc-1", &format!("src-{}", KNOWN_SOURCES_CAP + 2), now));
    }
}
