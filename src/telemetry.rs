//! Packed 256-byte telemetry block plus an append-only event ticker.
//!
//! Request threads only update memory. A writer thread publishes the block
//! with a temp file and rename so the monitor never reads a torn write, and
//! so disk latency stays out of the reflex path.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::schema::RouteAction;

pub const TELEMETRY_BYTES: usize = 256;
pub const TELEMETRY_MAGIC: &[u8; 4] = b"NX0S";

const FLUSH_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub seq: u64,
    pub requests_total: u64,
    pub dropped: u64,
    pub quarantine: u64,
    pub pii_spans: u64,
    pub extract_spans: u64,
    pub entropy_flags: u64,
    pub last_latency_ns: u64,
    pub ema_latency_ns: u64,
    pub min_latency_ns: u64,
    pub max_latency_ns: u64,
    pub last_malicious: f32,
    pub last_pii: f32,
    pub last_entropy: f32,
    pub last_ai: f32,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub active_conns: u32,
    pub last_route: u32,
    pub histogram: [u32; 16],
    pub bytes_redacted: u64,
    pub protocol_errors: u64,
    /// Duration of the last stats-file publish. Separate from reflex latency.
    pub last_publish_ns: u64,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            seq: 0,
            requests_total: 0,
            dropped: 0,
            quarantine: 0,
            pii_spans: 0,
            extract_spans: 0,
            entropy_flags: 0,
            last_latency_ns: 0,
            ema_latency_ns: 0,
            min_latency_ns: u64::MAX,
            max_latency_ns: 0,
            last_malicious: 0.0,
            last_pii: 0.0,
            last_entropy: 0.0,
            last_ai: 0.0,
            bytes_in: 0,
            bytes_out: 0,
            active_conns: 0,
            last_route: 0,
            histogram: [0; 16],
            bytes_redacted: 0,
            protocol_errors: 0,
            last_publish_ns: 0,
        }
    }
}

struct State {
    snap: Snapshot,
    events: Vec<String>,
    dirty: bool,
}

struct Shared {
    inner: Mutex<State>,
    publish: Mutex<()>,
    stats_path: PathBuf,
    events_path: PathBuf,
    started: Instant,
    shutdown: AtomicBool,
}

pub struct Telemetry {
    shared: Arc<Shared>,
    writer: Option<JoinHandle<()>>,
}

impl Telemetry {
    pub fn new(stats_path: PathBuf, events_path: PathBuf) -> Self {
        if let Some(parent) = stats_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let shared = Arc::new(Shared {
            inner: Mutex::new(State {
                snap: Snapshot::default(),
                events: Vec::new(),
                dirty: false,
            }),
            publish: Mutex::new(()),
            stats_path,
            events_path,
            started: Instant::now(),
            shutdown: AtomicBool::new(false),
        });
        let worker = Arc::clone(&shared);
        let writer = thread::Builder::new()
            .name("nexus0-telemetry".into())
            .spawn(move || writer_loop(&worker))
            .ok();
        Self { shared, writer }
    }

    pub fn record_error(&self, kind: &str) {
        if let Ok(mut state) = self.shared.inner.lock() {
            state.snap.protocol_errors += 1;
            state.events.push(format!("ERROR,{kind}"));
            state.dirty = true;
        }
    }

    pub fn conn_delta(&self, delta: i32) {
        if let Ok(mut state) = self.shared.inner.lock() {
            let next = state.snap.active_conns as i32 + delta;
            state.snap.active_conns = next.max(0) as u32;
            state.dirty = true;
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        seq: u64,
        route: RouteAction,
        latency_ns: u64,
        malicious: f32,
        pii: f32,
        entropy: f32,
        ai: f32,
        span_count: u64,
        pii_span_count: u64,
        bytes_in: u64,
        bytes_out: u64,
        bytes_redacted: u64,
    ) {
        let line = format!(
            "{seq},{},{latency_ns},{malicious:.3},{pii:.3},{entropy:.2},{ai:.3},{span_count}",
            route.as_str()
        );
        if let Ok(mut state) = self.shared.inner.lock() {
            let s = &mut state.snap;
            s.seq = seq;
            s.requests_total += 1;
            match route {
                RouteAction::Drop => s.dropped += 1,
                RouteAction::Quarantine => s.quarantine += 1,
                RouteAction::Accept => {}
            }
            s.pii_spans += pii_span_count;
            s.extract_spans += span_count;
            if ai >= 0.70 {
                s.entropy_flags += 1;
            }
            s.last_latency_ns = latency_ns;
            if s.ema_latency_ns == 0 {
                s.ema_latency_ns = latency_ns;
            } else {
                s.ema_latency_ns =
                    ((s.ema_latency_ns as f64) * 0.9 + latency_ns as f64 * 0.1) as u64;
            }
            s.min_latency_ns = s.min_latency_ns.min(latency_ns);
            s.max_latency_ns = s.max_latency_ns.max(latency_ns);
            s.last_malicious = malicious;
            s.last_pii = pii;
            s.last_entropy = entropy;
            s.last_ai = ai;
            s.bytes_in += bytes_in;
            s.bytes_out += bytes_out;
            s.bytes_redacted += bytes_redacted;
            s.last_route = route as u32;
            s.histogram[latency_bucket(latency_ns)] += 1;
            state.events.push(line);
            state.dirty = true;
        }
    }

    /// Publish the current snapshot. Tests and shutdown call this directly.
    pub fn flush(&self) {
        publish(&self.shared);
    }

    pub fn stats_path(&self) -> &Path {
        &self.shared.stats_path
    }
}

impl Drop for Telemetry {
    fn drop(&mut self) {
        self.shared.shutdown.store(true, Ordering::Relaxed);
        publish(&self.shared);
        if let Some(handle) = self.writer.take() {
            let _ = handle.join();
        }
    }
}

fn writer_loop(shared: &Shared) {
    while !shared.shutdown.load(Ordering::Relaxed) {
        thread::sleep(FLUSH_INTERVAL);
        publish(shared);
    }
    publish(shared);
}

fn publish(shared: &Shared) {
    let Ok(_gate) = shared.publish.lock() else {
        return;
    };
    let started = Instant::now();
    let (packed, events) = {
        let Ok(mut state) = shared.inner.lock() else {
            return;
        };
        if !state.dirty && state.events.is_empty() {
            return;
        }
        let packed = pack(&state.snap, shared.started.elapsed().as_millis() as u64);
        state.dirty = false;
        let events = std::mem::take(&mut state.events);
        (packed, events)
    };

    if atomic_write(&shared.stats_path, &packed).is_err() {
        if let Ok(mut state) = shared.inner.lock() {
            state.events.splice(0..0, events);
            state.dirty = true;
        }
        return;
    }
    append_events(&shared.events_path, &events);

    let publish_ns = started.elapsed().as_nanos() as u64;
    let repacked = {
        let Ok(mut state) = shared.inner.lock() else {
            return;
        };
        state.snap.last_publish_ns = publish_ns;
        pack(&state.snap, shared.started.elapsed().as_millis() as u64)
    };
    let _ = atomic_write(&shared.stats_path, &repacked);
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = publishing_path(path);
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.flush()?;
    }
    replace_file(&tmp, path)
}

fn publishing_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".publishing");
    path.with_file_name(name)
}

fn replace_file(from: &Path, to: &Path) -> std::io::Result<()> {
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    let _ = fs::remove_file(to);
    fs::rename(from, to)
}

pub fn latency_bucket(ns: u64) -> usize {
    let us = ns / 1000;
    let mut b = 0usize;
    let mut cap = 1u64;
    while b < 15 && us >= cap {
        cap = cap.saturating_mul(2);
        b += 1;
    }
    b
}

fn pack(s: &Snapshot, uptime_ms: u64) -> [u8; TELEMETRY_BYTES] {
    let mut buf = [0u8; TELEMETRY_BYTES];
    buf[0..4].copy_from_slice(TELEMETRY_MAGIC);
    buf[4..8].copy_from_slice(&1u32.to_le_bytes());
    buf[8..16].copy_from_slice(&s.seq.to_le_bytes());
    buf[16..24].copy_from_slice(&s.requests_total.to_le_bytes());
    buf[24..32].copy_from_slice(&s.dropped.to_le_bytes());
    buf[32..40].copy_from_slice(&s.quarantine.to_le_bytes());
    buf[40..48].copy_from_slice(&s.pii_spans.to_le_bytes());
    buf[48..56].copy_from_slice(&s.extract_spans.to_le_bytes());
    buf[56..64].copy_from_slice(&s.entropy_flags.to_le_bytes());
    buf[64..72].copy_from_slice(&s.last_latency_ns.to_le_bytes());
    buf[72..80].copy_from_slice(&s.ema_latency_ns.to_le_bytes());
    let min = if s.min_latency_ns == u64::MAX {
        0
    } else {
        s.min_latency_ns
    };
    buf[80..88].copy_from_slice(&min.to_le_bytes());
    buf[88..96].copy_from_slice(&s.max_latency_ns.to_le_bytes());
    buf[96..100].copy_from_slice(&s.last_malicious.to_le_bytes());
    buf[100..104].copy_from_slice(&s.last_pii.to_le_bytes());
    buf[104..108].copy_from_slice(&s.last_entropy.to_le_bytes());
    buf[108..112].copy_from_slice(&s.last_ai.to_le_bytes());
    buf[112..120].copy_from_slice(&s.bytes_in.to_le_bytes());
    buf[120..128].copy_from_slice(&s.bytes_out.to_le_bytes());
    buf[128..132].copy_from_slice(&s.active_conns.to_le_bytes());
    buf[132..136].copy_from_slice(&s.last_route.to_le_bytes());
    for i in 0..16 {
        let off = 136 + i * 4;
        buf[off..off + 4].copy_from_slice(&s.histogram[i].to_le_bytes());
    }
    buf[200..208].copy_from_slice(&s.bytes_redacted.to_le_bytes());
    buf[208..216].copy_from_slice(&uptime_ms.to_le_bytes());
    buf[216..224].copy_from_slice(&s.protocol_errors.to_le_bytes());
    buf[224..232].copy_from_slice(&s.last_publish_ns.to_le_bytes());
    buf
}

fn append_events(path: &Path, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    if let Ok(meta) = fs::metadata(path) {
        if meta.len() > 512 * 1024 {
            let _ = fs::remove_file(path);
        }
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        for line in lines {
            let _ = writeln!(file, "{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_roundtrip_magic() {
        let s = Snapshot::default();
        let buf = pack(&s, 10);
        assert_eq!(&buf[0..4], b"NX0S");
        assert_eq!(buf.len(), 256);
        assert_eq!(u64::from_le_bytes(buf[224..232].try_into().unwrap()), 0);
    }

    #[test]
    fn protocol_error_counter_is_visible() {
        let dir = std::env::temp_dir();
        let stats = dir.join(format!(
            "nexus0-err-{}-{}.stats",
            std::process::id(),
            unique_suffix()
        ));
        let events = dir.join(format!(
            "nexus0-err-{}-{}.events",
            std::process::id(),
            unique_suffix()
        ));
        let tel = Telemetry::new(stats.clone(), events);
        tel.record_error("bad_header");
        tel.flush();
        let buf = std::fs::read(&stats).expect("stats written");
        assert_eq!(&buf[0..4], b"NX0S");
        assert_eq!(u64::from_le_bytes(buf[216..224].try_into().unwrap()), 1);
        let _ = std::fs::remove_file(&stats);
    }

    fn unique_suffix() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        N.fetch_add(1, Ordering::Relaxed)
    }

    #[test]
    fn bucket_edges() {
        assert_eq!(latency_bucket(0), 0);
        assert_eq!(latency_bucket(500), 0);
        assert_eq!(latency_bucket(1000), 1);
        assert_eq!(latency_bucket(16_000_000), 14);
        assert_eq!(latency_bucket(16_384_000), 15);
    }
}
