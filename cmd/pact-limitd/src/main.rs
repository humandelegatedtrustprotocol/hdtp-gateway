//! pact-limitd: the node's limits sidecar (layer 2 of docs/release/two-layer-limits-2026-09-28.md).
//!
//!   pact-limitd -config /data/limits.json
//!
//! Reads its configuration (the socket path and the rules), refuses one it cannot enforce, listens
//! on the socket, and answers one JSON object a line (src/lib.rs). One process holds one counter for
//! every account and every node process on the host; a node that cannot reach it refuses every
//! sealed call `unavailable` until it can (§6 of the plan).

use pact_limitd::{handle, read_config, Store};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::{env, fs, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = match args.as_slice() {
        [_, flag, path] if flag == "-config" || flag == "--config" => path.clone(),
        _ => {
            eprintln!("usage: pact-limitd -config <file>");
            process::exit(2);
        }
    };
    let text = fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("pact-limitd: {path}: {e}");
        process::exit(2);
    });
    let config = read_config(&text).unwrap_or_else(|why| {
        eprintln!("pact-limitd: {path}: {why}");
        process::exit(2);
    });
    // A socket file left by an earlier run refuses the bind; nothing else owns this path.
    let _ = fs::remove_file(&config.socket);
    let listener = UnixListener::bind(&config.socket).unwrap_or_else(|e| {
        eprintln!("pact-limitd: listen {}: {e}", config.socket);
        process::exit(1);
    });
    println!("pact-limitd serving: socket={} rules={}", config.socket, serde_json::Value::Object(config.rules_doc.clone()));
    let store = Arc::new(Mutex::new(Store::default()));
    let config = Arc::new(config);
    for conn in listener.incoming() {
        let conn = match conn {
            Ok(c) => c,
            Err(e) => {
                eprintln!("pact-limitd: accept: {e}");
                continue;
            }
        };
        let store = Arc::clone(&store);
        let config = Arc::clone(&config);
        std::thread::spawn(move || serve(conn, &config, &store));
    }
}

fn serve(conn: UnixStream, config: &pact_limitd::Config, store: &Mutex<Store>) {
    let mut writer = match conn.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    for line in BufReader::new(conn).lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => return,
        };
        if line.trim().is_empty() {
            continue;
        }
        let answer = {
            let mut s = store.lock().unwrap_or_else(|e| e.into_inner());
            handle(&config.rules, &config.rules_doc, &mut s, &line)
        };
        if writer.write_all(answer.as_bytes()).and_then(|()| writer.write_all(b"\n")).is_err() {
            return;
        }
    }
}
