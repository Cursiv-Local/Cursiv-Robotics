//! cursiv-bridge: headless ingestion service for robot observations.
//!
//!   cursiv-bridge keygen <key-file>
//!   cursiv-bridge serve --store <dir> --station-id <id> --key <key-file> --trust <trust.json>
//!                       [--bind 127.0.0.1:8750] [--token-file <file>] [--queue 256] [--workers 4]
//!
//! Security: binds loopback only unless an API token is configured; checks the Host
//! header (DNS-rebinding defence, as Cursiv's Field Station server does); refuses
//! browser-originated writes (Origin header); caps body sizes; never commands a robot.
//! Writes go through a bounded queue to one batching writer; a full queue answers 503.

use cursiv_evidence::crypto::{Envelope, Identity};
use cursiv_evidence::store::{Outcome, Store};
use cursiv_evidence::trust::TrustStore;
use cursiv_evidence::{model, verify};
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tiny_http::{Header, Method, Request, Response, Server};

const MAX_JSON_BODY: usize = 8 * 1024 * 1024;
const MAX_BATCH: usize = 1000;
const OPENAPI: &str = include_str!("../../../docs/openapi.json");

struct Job {
    envs: Vec<Envelope>,
    reply: std::sync::mpsc::Sender<Result<Vec<Outcome>, String>>,
}

struct App {
    store: Arc<Mutex<Store>>,
    jobs: SyncSender<Job>,
    token: Option<String>,
    port: u16,
    trust_path: PathBuf,
    exports: PathBuf,
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn json(status: u16, body: serde_json::Value) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body.to_string())
        .with_status_code(status)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap())
        .with_header(Header::from_bytes("X-Content-Type-Options", "nosniff").unwrap())
}

fn err(status: u16, code: &str, detail: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    json(status, serde_json::json!({"error": code, "detail": detail}))
}

fn header<'a>(req: &'a Request, name: &'static str) -> Option<&'a str> {
    req.headers().iter().find(|h| h.field.equiv(name)).map(|h| h.value.as_str())
}

fn read_body(req: &mut Request, limit: usize) -> Result<Vec<u8>, Response<std::io::Cursor<Vec<u8>>>> {
    if req.body_length().is_some_and(|n| n > limit) {
        return Err(err(413, "too_large", &format!("body exceeds {limit} bytes")));
    }
    let mut buf = Vec::new();
    req.as_reader().take(limit as u64 + 1).read_to_end(&mut buf).map_err(|e| err(400, "read_failed", &e.to_string()))?;
    if buf.len() > limit {
        return Err(err(413, "too_large", &format!("body exceeds {limit} bytes")));
    }
    Ok(buf)
}

/// Single writer: coalesces queued jobs into one fsynced batch.
fn writer(store: Arc<Mutex<Store>>, rx: Receiver<Job>) {
    while let Ok(first) = rx.recv() {
        let mut jobs = vec![first];
        let mut n = jobs[0].envs.len();
        while n < 5000 && jobs.len() < 64 {
            match rx.try_recv() {
                Ok(j) => {
                    n += j.envs.len();
                    jobs.push(j)
                }
                Err(_) => break,
            }
        }
        let all: Vec<Envelope> = jobs.iter().flat_map(|j| j.envs.iter().cloned()).collect();
        let result = store.lock().unwrap().ingest_batch(&all);
        match result {
            Ok(outcomes) => {
                let mut it = outcomes.into_iter();
                for j in jobs {
                    let part: Vec<Outcome> = it.by_ref().take(j.envs.len()).collect();
                    let _ = j.reply.send(Ok(part));
                }
            }
            Err(e) => {
                for j in jobs {
                    let _ = j.reply.send(Err(e.clone()));
                }
            }
        }
    }
}

impl App {
    fn host_ok(&self, req: &Request) -> bool {
        let Some(h) = header(req, "Host") else { return false };
        let h = h.to_ascii_lowercase();
        let port = self.port;
        [format!("127.0.0.1:{port}"), format!("localhost:{port}"), format!("[::1]:{port}")].contains(&h)
            || (self.token.is_some() && h.ends_with(&format!(":{port}")))
    }

    fn authorized(&self, req: &Request) -> bool {
        match &self.token {
            None => true,
            Some(t) => header(req, "Authorization").is_some_and(|a| {
                let expected = format!("Bearer {t}");
                a.len() == expected.len() && a.bytes().zip(expected.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
            }),
        }
    }

    fn submit(&self, envs: Vec<Envelope>) -> Response<std::io::Cursor<Vec<u8>>> {
        let (tx, rx) = std::sync::mpsc::channel();
        match self.jobs.try_send(Job { envs, reply: tx }) {
            Err(TrySendError::Full(_)) => {
                return err(503, "busy", "ingest queue is full; retry after the Retry-After delay")
                    .with_header(Header::from_bytes("Retry-After", "1").unwrap());
            }
            Err(TrySendError::Disconnected(_)) => return err(503, "writer_stopped", "the writer stopped; restart the service"),
            Ok(()) => {}
        }
        match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(Ok(outcomes)) => {
                let worst = outcomes.iter().map(|o| o.http_status()).max().unwrap_or(200);
                let status = if outcomes.len() == 1 { worst } else { 207 };
                let accepted = outcomes.iter().filter(|o| matches!(o, Outcome::Accepted { .. })).count();
                json(status, serde_json::json!({"accepted": accepted, "results": outcomes}))
            }
            Ok(Err(e)) => err(500, "write_failed", &e),
            Err(_) => err(504, "timeout", "the write did not complete in time; the outcome is unknown, retry (retries are idempotent)"),
        }
    }

    fn handle(&self, mut req: Request) {
        let url = req.url().to_string();
        let path = url.split('?').next().unwrap_or("").to_string();
        let method = req.method().clone();
        let resp = if !self.host_ok(&req) {
            err(421, "bad_host", "Host header must name this service on loopback")
        } else if header(&req, "Origin").is_some() && method != Method::Get {
            err(403, "browser_origin", "requests from web pages are refused")
        } else if path != "/v1/health" && !self.authorized(&req) {
            err(401, "unauthorized", "missing or wrong bearer token")
        } else {
            self.route(&mut req, &method, &path)
        };
        let _ = req.respond(resp);
    }

    fn route(&self, req: &mut Request, method: &Method, path: &str) -> Response<std::io::Cursor<Vec<u8>>> {
        let seg: Vec<&str> = path.trim_matches('/').split('/').collect();
        match (method, seg.as_slice()) {
            (Method::Get, ["v1", "health"]) => json(200, serde_json::json!({"status": "ok", "service": "cursiv-bridge", "version": env!("CARGO_PKG_VERSION"), "time": model::now_utc()})),
            (Method::Get, ["v1", "openapi.json"]) => Response::from_string(OPENAPI).with_header(Header::from_bytes("Content-Type", "application/json").unwrap()),
            (Method::Get, ["v1", "status"]) => json(200, self.store.lock().unwrap().status()),
            (Method::Get, ["v1", "robots", id, "head"]) => {
                if !model::valid_id(id) {
                    return err(400, "bad_robot_id", "invalid robot id");
                }
                let s = self.store.lock().unwrap();
                let st = s.status();
                let r = &st["robots"][*id];
                json(200, serde_json::json!({"robot_id": id, "count": r["records"].as_u64().unwrap_or(0), "head": r["head"].as_str().unwrap_or(model::GENESIS)}))
            }
            (Method::Post, ["v1", "observations"]) => {
                let body = match read_body(req, MAX_JSON_BODY) { Ok(b) => b, Err(r) => return r };
                let v: serde_json::Value = match serde_json::from_slice(&body) { Ok(v) => v, Err(e) => return err(400, "malformed_json", &e.to_string()) };
                let envs: Result<Vec<Envelope>, _> = if v.get("records").is_some() {
                    serde_json::from_value(v["records"].clone())
                } else {
                    serde_json::from_value(v).map(|e| vec![e])
                };
                match envs {
                    Err(e) => err(400, "malformed_envelope", &e.to_string()),
                    Ok(e) if e.is_empty() || e.len() > MAX_BATCH => err(400, "batch_size", &format!("send 1 to {MAX_BATCH} records")),
                    Ok(e) => self.submit(e),
                }
            }
            (Method::Post, ["v1", "checkpoints"]) => {
                let body = match read_body(req, 64 * 1024) { Ok(b) => b, Err(r) => return r };
                match serde_json::from_slice::<Envelope>(&body) {
                    Err(e) => err(400, "malformed_envelope", &e.to_string()),
                    Ok(env) => {
                        let o = self.store.lock().unwrap().ingest_checkpoint(&env);
                        json(o.http_status(), serde_json::to_value(&o).unwrap())
                    }
                }
            }
            (Method::Put, ["v1", "attachments", sha]) => {
                let Some(len) = req.body_length() else { return err(411, "length_required", "Content-Length is required") };
                let blobs = self.store.lock().unwrap().blobs();
                match blobs.put(req.as_reader(), sha, len as u64) {
                    Ok(true) => json(201, serde_json::json!({"sha256": sha, "stored": true})),
                    Ok(false) => json(200, serde_json::json!({"sha256": sha, "stored": false, "note": "already present"})),
                    Err((code, msg)) => err(code, "attachment_rejected", &msg),
                }
            }
            (Method::Get, ["v1", "attachments", sha]) => {
                let present = self.store.lock().unwrap().has_blob(sha);
                json(if present { 200 } else { 404 }, serde_json::json!({"sha256": sha, "present": present}))
            }
            (Method::Post, ["v1", "exports"]) => {
                let body = match read_body(req, 4096) { Ok(b) => b, Err(r) => return r };
                let name = serde_json::from_slice::<serde_json::Value>(&body).ok().and_then(|v| v["name"].as_str().map(String::from)).unwrap_or_default();
                if !model::valid_id(&name) {
                    return err(400, "bad_name", "export name must be 1-64 of [a-z0-9._-]");
                }
                let dest = self.exports.join(&name);
                match self.store.lock().unwrap().export(&dest) {
                    Ok(v) => json(201, v),
                    Err(e) => err(409, "export_failed", &e),
                }
            }
            (Method::Post, ["v1", "verify"]) => {
                // Only packages this service exported can be named: no arbitrary file paths.
                let body = match read_body(req, 4096) { Ok(b) => b, Err(r) => return r };
                let name = serde_json::from_slice::<serde_json::Value>(&body).ok().and_then(|v| v["package"].as_str().map(String::from)).unwrap_or_default();
                if !model::valid_id(&name) {
                    return err(400, "bad_name", "package must be the name of an export");
                }
                let trust = self.store.lock().unwrap().trust().clone();
                let r = verify::verify_package(&self.exports.join(&name), Some(&trust));
                json(200, serde_json::to_value(&r).unwrap())
            }
            (Method::Post, ["v1", "trust", "reload"]) => match TrustStore::load(&self.trust_path) {
                Ok(_) => err(501, "restart_required", "trust store changes take effect on restart in this version"),
                Err(e) => err(400, "trust_invalid", &e),
            },
            _ => err(404, "not_found", "no such endpoint"),
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") => {
            let Some(path) = args.get(1) else {
                eprintln!("usage: cursiv-bridge keygen <key-file>");
                std::process::exit(2)
            };
            let id = Identity::generate();
            if let Err(e) = id.save(path.as_ref()) {
                eprintln!("{e}");
                std::process::exit(1)
            }
            println!("{}", serde_json::json!({"key_id": id.key_id(), "public_key": cursiv_evidence::crypto::public_b64(&id.public())}));
        }
        Some("serve") => serve(&args),
        _ => {
            eprintln!("usage:\n  cursiv-bridge keygen <key-file>\n  cursiv-bridge serve --store DIR --station-id ID --key FILE --trust FILE [--bind 127.0.0.1:8750] [--token-file F] [--queue 256] [--workers 4]");
            std::process::exit(2)
        }
    }
}

fn serve(args: &[String]) {
    let need = |n: &str| arg(args, n).unwrap_or_else(|| {
        eprintln!("missing {n}");
        std::process::exit(2)
    });
    let store_dir = PathBuf::from(need("--store"));
    let station_id = need("--station-id");
    let key = Identity::load(need("--key").as_ref()).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1)
    });
    let trust_path = PathBuf::from(need("--trust"));
    let trust = TrustStore::load(&trust_path).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1)
    });
    let bind: SocketAddr = arg(args, "--bind").unwrap_or_else(|| "127.0.0.1:8750".into()).parse().unwrap_or_else(|_| {
        eprintln!("--bind must be address:port");
        std::process::exit(2)
    });
    let token = arg(args, "--token-file").map(|p| std::fs::read_to_string(p).expect("token file").trim().to_string());
    if token.as_ref().is_some_and(|t| t.len() < 32) {
        eprintln!("the API token must be at least 32 characters");
        std::process::exit(2)
    }
    if !bind.ip().is_loopback() && token.is_none() {
        eprintln!("refusing to listen on {bind} without --token-file: off-host access needs authentication");
        std::process::exit(2)
    }
    let queue: usize = arg(args, "--queue").and_then(|q| q.parse().ok()).unwrap_or(256);
    let workers: usize = arg(args, "--workers").and_then(|q| q.parse().ok()).unwrap_or(4).clamp(1, 64);
    let store = Store::open(&store_dir, &station_id, key, trust).unwrap_or_else(|e| {
        eprintln!("cannot open store: {e}");
        std::process::exit(1)
    });
    for n in &store.recovery_notes {
        eprintln!("recovery: {n}");
    }
    let store = Arc::new(Mutex::new(store));
    let (tx, rx) = sync_channel::<Job>(queue);
    {
        let s = store.clone();
        std::thread::spawn(move || writer(s, rx));
    }
    let server = Arc::new(Server::http(bind).unwrap_or_else(|e| {
        eprintln!("cannot listen on {bind}: {e}");
        std::process::exit(1)
    }));
    let port = server.server_addr().to_ip().map(|a| a.port()).unwrap_or(bind.port());
    let app = Arc::new(App { store, jobs: tx, token, port, trust_path, exports: store_dir.join("exports") });
    println!("{}", serde_json::json!({"listening": format!("{}:{port}", bind.ip()), "store": store_dir.display().to_string(), "station_id": station_id}));
    let mut handles = Vec::new();
    for _ in 0..workers {
        let (server, app) = (server.clone(), app.clone());
        handles.push(std::thread::spawn(move || {
            while let Ok(req) = server.recv() {
                app.handle(req);
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
}
