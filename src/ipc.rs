//! Cross-platform reflex server: Unix domain sockets, TCP fallback on Windows.
//!
//! The accept loop is non-blocking so Ctrl-C can stop the process, flush
//! telemetry, and wait for in-flight sessions. Session count is capped.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::client::is_tcp;
#[cfg(unix)]
use crate::config::default_runtime_dir;
use crate::config::Config;
use crate::engine::ReflexEngine;
use crate::schema::{
    decode_request_header, encode_response, Opcode, Response, RouteAction, FLAG_APPLY_REDACT,
    REQUEST_HEADER_LEN, STATUS_DROPPED, STATUS_ERROR, STATUS_OK, STATUS_QUARANTINE,
};
use crate::telemetry::Telemetry;

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_PAUSE: Duration = Duration::from_millis(25);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

thread_local! {
    static PAYLOAD_BUF: std::cell::RefCell<Vec<u8>> =
        std::cell::RefCell::new(Vec::with_capacity(4096));
    static WIRE_BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(512));
}

pub fn run(cfg: Config) -> io::Result<()> {
    install_shutdown_hook();
    let _ = tighten_dir(&cfg.quarantine_dir);
    if let Some(parent) = cfg.stats_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let core = Core {
        engine: Arc::new(ReflexEngine::from_config(&cfg)),
        telemetry: Arc::new(Telemetry::new(
            cfg.stats_path.clone(),
            cfg.events_path.clone(),
        )),
        seq: Arc::new(AtomicU64::new(1)),
        sessions: Arc::new(AtomicUsize::new(0)),
        max_payload: cfg.max_payload,
        max_sessions: cfg.max_sessions.max(1),
        quarantine_dir: cfg.quarantine_dir.clone(),
    };

    eprintln!("NEXUS-0 reflex core {}", crate::VERSION);
    eprintln!("  bind        {}", cfg.bind);
    eprintln!("  stats       {}", cfg.stats_path.display());
    eprintln!("  events      {}", cfg.events_path.display());
    eprintln!("  quarantine  {}", cfg.quarantine_dir.display());
    eprintln!("  sessions    at most {}", core.max_sessions);
    eprintln!(
        "  thresholds  quarantine {:.2}  drop {:.2} (drop needs FLAG_DROP_IF_MALICIOUS)",
        cfg.quarantine_threshold, cfg.drop_threshold
    );

    let result = if is_tcp(&cfg.bind) {
        run_tcp(&cfg, &core)
    } else {
        run_unix(&cfg, &core)
    };

    wait_for_sessions(&core.sessions);
    core.telemetry.flush();
    result
}

#[derive(Clone)]
struct Core {
    engine: Arc<ReflexEngine>,
    telemetry: Arc<Telemetry>,
    seq: Arc<AtomicU64>,
    sessions: Arc<AtomicUsize>,
    max_payload: usize,
    max_sessions: usize,
    quarantine_dir: PathBuf,
}

fn run_tcp(cfg: &Config, core: &Core) -> io::Result<()> {
    if let Ok(addr) = cfg.bind.parse::<std::net::SocketAddr>() {
        if !addr.ip().is_loopback() && !cfg.allow_remote {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{addr} is not loopback; pass --allow-remote to accept non-local clients"),
            ));
        }
    }
    let listener = TcpListener::bind(&cfg.bind)?;
    listener.set_nonblocking(true)?;
    accept_loop(|| listener.accept().map(|(stream, _)| stream), core)
}

fn run_unix(cfg: &Config, core: &Core) -> io::Result<()> {
    #[cfg(unix)]
    {
        let listener = bind_unix_socket(Path::new(&cfg.bind))?;
        listener.set_nonblocking(true)?;
        return accept_loop(|| listener.accept().map(|(stream, _)| stream), core);
    }

    #[cfg(not(unix))]
    {
        let _ = core;
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "bind '{}' is not a TCP address; on Windows use --bind 127.0.0.1:9800",
                cfg.bind
            ),
        ))
    }
}

trait Accepted: Read + Write + Send + 'static {
    fn prepare(&self) -> io::Result<()>;
}

impl Accepted for TcpStream {
    fn prepare(&self) -> io::Result<()> {
        self.set_nonblocking(false)?;
        self.set_read_timeout(Some(IO_TIMEOUT))?;
        self.set_write_timeout(Some(IO_TIMEOUT))?;
        self.set_nodelay(true)?;
        Ok(())
    }
}

#[cfg(unix)]
impl Accepted for std::os::unix::net::UnixStream {
    fn prepare(&self) -> io::Result<()> {
        self.set_nonblocking(false)?;
        self.set_read_timeout(Some(IO_TIMEOUT))?;
        self.set_write_timeout(Some(IO_TIMEOUT))?;
        Ok(())
    }
}

fn accept_loop<S, F>(mut accept: F, core: &Core) -> io::Result<()>
where
    S: Accepted,
    F: FnMut() -> io::Result<S>,
{
    while !SHUTDOWN.load(Ordering::Relaxed) {
        match accept() {
            Ok(stream) => {
                if let Err(e) = stream.prepare() {
                    core.telemetry.record_error("accept");
                    eprintln!("session setup failed: {e}");
                    continue;
                }
                spawn_session(stream, core.clone());
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::Interrupted =>
            {
                thread::sleep(ACCEPT_PAUSE);
            }
            Err(e) => {
                core.telemetry.record_error("accept");
                eprintln!("accept error: {e}");
                thread::sleep(ACCEPT_PAUSE);
            }
        }
    }
    eprintln!("nexus-0: shutting down");
    Ok(())
}

fn spawn_session<S>(stream: S, core: Core)
where
    S: Read + Write + Send + 'static,
{
    if !try_acquire(&core.sessions, core.max_sessions) {
        core.telemetry.record_error("busy");
        eprintln!(
            "nexus-0: refusing connection, {} sessions already open",
            core.max_sessions
        );
        return;
    }
    thread::spawn(move || {
        core.telemetry.conn_delta(1);
        match catch_unwind(AssertUnwindSafe(|| {
            session_loop(
                stream,
                &core.engine,
                &core.telemetry,
                &core.seq,
                core.max_payload,
                &core.quarantine_dir,
            )
        })) {
            Ok(Ok(())) => {}
            Ok(Err(e))
                if e.kind() == io::ErrorKind::UnexpectedEof
                    || e.kind() == io::ErrorKind::TimedOut => {}
            Ok(Err(e)) => {
                core.telemetry.record_error("session");
                eprintln!("session error: {e}");
            }
            Err(_) => {
                core.telemetry.record_error("panic");
                eprintln!("session panic");
            }
        }
        core.telemetry.conn_delta(-1);
        core.sessions.fetch_sub(1, Ordering::AcqRel);
    });
}

fn session_loop<S: Read + Write>(
    mut stream: S,
    engine: &ReflexEngine,
    telemetry: &Telemetry,
    seq: &AtomicU64,
    max_payload: usize,
    quarantine_dir: &Path,
) -> io::Result<()> {
    loop {
        if SHUTDOWN.load(Ordering::Relaxed) {
            return Ok(());
        }
        match serve_one(
            &mut stream,
            engine,
            telemetry,
            seq,
            max_payload,
            quarantine_dir,
        ) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}

fn serve_one<S: Read + Write>(
    stream: &mut S,
    engine: &ReflexEngine,
    telemetry: &Telemetry,
    seq: &AtomicU64,
    max_payload: usize,
    quarantine_dir: &Path,
) -> io::Result<()> {
    let mut header = [0u8; REQUEST_HEADER_LEN];
    stream.read_exact(&mut header)?;
    let (opcode, flags, req_seq, len) = match decode_request_header(&header) {
        Ok(v) => v,
        Err(e) => {
            telemetry.record_error("bad_header");
            return Err(io::Error::new(io::ErrorKind::InvalidData, e));
        }
    };
    if len as usize > max_payload {
        telemetry.record_error("payload_too_large");
        let _ = write_error(stream, opcode, req_seq);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "payload too large",
        ));
    }

    PAYLOAD_BUF.with(|slot| {
        let mut payload = slot.borrow_mut();
        payload.clear();
        payload.resize(len as usize, 0);
        if len > 0 {
            stream.read_exact(&mut payload)?;
        }
        let server_id = seq.fetch_add(1, Ordering::Relaxed);
        let resp_seq = if req_seq == 0 { server_id } else { req_seq };

        let evaluated = catch_unwind(AssertUnwindSafe(|| {
            engine.evaluate(opcode, flags, &payload)
        }));
        let decision = match evaluated {
            Ok(d) => d,
            Err(_) => {
                telemetry.record_error("panic");
                let _ = write_error(stream, opcode, resp_seq);
                return Ok(());
            }
        };

        let mut stored_spans = 0u64;
        if decision.route == RouteAction::Quarantine {
            match write_quarantine(engine, quarantine_dir, server_id, &payload) {
                Ok(n) => stored_spans = n,
                Err(e) => {
                    telemetry.record_error("quarantine");
                    eprintln!("quarantine write failed: {e}");
                    let _ = write_error(stream, opcode, resp_seq);
                    return Ok(());
                }
            }
        }

        let status = match decision.route {
            RouteAction::Accept => STATUS_OK,
            RouteAction::Quarantine => STATUS_QUARANTINE,
            RouteAction::Drop => STATUS_DROPPED,
        };

        let masked = flags & FLAG_APPLY_REDACT != 0 || opcode == Opcode::Redact;
        let extract_spans = decision.spans.len() as u64;
        let pii_spans = if masked { extract_spans } else { stored_spans };
        let bytes_redacted = if masked {
            decision.spans.iter().map(|s| s.len() as u64).sum()
        } else {
            0
        };

        let route = decision.route;
        let latency_ns = decision.latency_ns;
        let malicious = decision.malicious;
        let pii = decision.pii;
        let entropy = decision.entropy;
        let ai_marker = decision.ai_marker;
        let resp = Response {
            status,
            opcode: decision.opcode,
            seq: resp_seq,
            latency_ns,
            malicious,
            pii,
            entropy,
            ai_marker,
            route,
            spans: decision.spans,
            payload: if route == RouteAction::Drop {
                None
            } else {
                decision.redacted
            },
            tools: decision.tools,
        };

        let out_len = resp.payload.as_ref().map(|p| p.len() as u64).unwrap_or(0);
        telemetry.record(
            resp_seq,
            route,
            latency_ns,
            malicious,
            pii,
            entropy,
            ai_marker,
            extract_spans,
            pii_spans,
            payload.len() as u64,
            out_len,
            bytes_redacted,
        );

        WIRE_BUF.with(|wire| {
            let mut wire = wire.borrow_mut();
            encode_response(&resp, &mut wire);
            stream.write_all(&wire)?;
            stream.flush()
        })
    })
}

fn write_quarantine(
    engine: &ReflexEngine,
    dir: &Path,
    server_id: u64,
    payload: &[u8],
) -> io::Result<u64> {
    let _ = tighten_dir(dir);
    let mut stored = payload.to_vec();
    let spans = engine.redact_buffer(&mut stored);
    let path = dir.join(format!("{server_id}.bin"));
    fs::write(&path, &stored)?;
    restrict_file(&path)?;
    Ok(spans.len() as u64)
}

fn write_error<S: Write>(stream: &mut S, opcode: Opcode, seq: u64) -> io::Result<()> {
    let resp = Response {
        status: STATUS_ERROR,
        opcode,
        seq,
        latency_ns: 0,
        malicious: 0.0,
        pii: 0.0,
        entropy: 0.0,
        ai_marker: 0.0,
        route: RouteAction::Drop,
        spans: Vec::new(),
        payload: None,
        tools: None,
    };
    let mut wire = Vec::new();
    encode_response(&resp, &mut wire);
    stream.write_all(&wire)?;
    stream.flush()
}

pub fn try_acquire(sessions: &AtomicUsize, max_sessions: usize) -> bool {
    let mut current = sessions.load(Ordering::Relaxed);
    loop {
        if current >= max_sessions {
            return false;
        }
        match sessions.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

fn wait_for_sessions(sessions: &AtomicUsize) {
    let deadline = Instant::now() + DRAIN_TIMEOUT;
    while sessions.load(Ordering::Relaxed) > 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
}

fn tighten_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path != std::env::temp_dir() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

fn restrict_file(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(unix)]
fn bind_unix_socket(path: &Path) -> io::Result<std::os::unix::net::UnixListener> {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path.parent() {
        if parent == std::env::temp_dir() {
            eprintln!(
                "warning: socket {} sits in the shared temp directory; prefer {}",
                path.display(),
                default_runtime_dir().join("nexus0.sock").display()
            );
        } else {
            tighten_dir(parent)?;
        }
    }
    if path.exists() || path.symlink_metadata().is_ok() {
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_socket() {
            fs::remove_file(path)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "bind path {} exists and is not a socket; refusing to replace it",
                    path.display()
                ),
            ));
        }
    }
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn install_shutdown_hook() {
    #[cfg(unix)]
    unsafe {
        signal(2, on_unix_signal as *const () as usize);
        signal(15, on_unix_signal as *const () as usize);
    }
    #[cfg(windows)]
    unsafe {
        SetConsoleCtrlHandler(Some(on_console), 1);
    }
}

#[cfg(unix)]
extern "C" fn on_unix_signal(_sig: i32) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

#[cfg(unix)]
extern "C" {
    fn signal(sig: i32, handler: usize) -> usize;
}

#[cfg(windows)]
extern "system" fn on_console(ctrl: u32) -> i32 {
    if ctrl == 0 || ctrl == 1 || ctrl == 2 {
        SHUTDOWN.store(true, Ordering::Relaxed);
        1
    } else {
        0
    }
}

#[cfg(windows)]
extern "system" {
    fn SetConsoleCtrlHandler(
        handler: Option<unsafe extern "system" fn(u32) -> i32>,
        add: i32,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_stops_at_the_cap() {
        let sessions = AtomicUsize::new(0);
        assert!(try_acquire(&sessions, 2));
        assert!(try_acquire(&sessions, 2));
        assert!(!try_acquire(&sessions, 2));
        assert_eq!(sessions.load(Ordering::Relaxed), 2);
    }
}
