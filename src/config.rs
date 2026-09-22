//! Runtime paths and bind addresses. Zero clap: argv + env only.
//!
//! Environment variables set the defaults. Explicit flags replace them.
//! Unknown flags and unparsable thresholds are errors.

use std::env;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    /// IPC bind target. Unix domain socket path, or `host:port` on Windows.
    pub bind: String,
    /// Packed telemetry block the monitor polls.
    pub stats_path: PathBuf,
    /// Append-only event ticker consumed by the dashboard.
    pub events_path: PathBuf,
    /// Directory for quarantined payloads (route = Quarantine).
    pub quarantine_dir: PathBuf,
    /// Malicious probability at or above this value can be dropped.
    /// Drop still requires [`crate::schema::FLAG_DROP_IF_MALICIOUS`].
    pub drop_threshold: f32,
    /// Malicious probability at or above this value (below drop) is quarantined.
    pub quarantine_threshold: f32,
    /// Maximum framed payload size in bytes.
    pub max_payload: usize,
    /// Concurrent sessions before new connections are refused.
    pub max_sessions: usize,
    /// Bind a non-loopback TCP address. Off unless set.
    pub allow_remote: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            stats_path: default_runtime_path("nexus0.stats"),
            events_path: default_runtime_path("nexus0.events"),
            quarantine_dir: default_runtime_path("quarantine"),
            drop_threshold: 0.95,
            quarantine_threshold: 0.80,
            max_payload: 1_048_576,
            max_sessions: 64,
            allow_remote: false,
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Help,
    Invalid(String),
}

impl Config {
    pub fn from_env_and_args() -> Result<Self, ConfigError> {
        let mut cfg = Config::default();
        apply_env(&mut cfg)?;
        apply_args(&mut cfg, env::args().skip(1))?;
        validate(&cfg)?;
        Ok(cfg)
    }
}

fn apply_env(cfg: &mut Config) -> Result<(), ConfigError> {
    if let Ok(v) = env::var("NEXUS0_BIND") {
        cfg.bind = v;
    }
    if let Ok(v) = env::var("NEXUS0_STATS") {
        cfg.stats_path = PathBuf::from(v);
    }
    if let Ok(v) = env::var("NEXUS0_EVENTS") {
        cfg.events_path = PathBuf::from(v);
    }
    if let Ok(v) = env::var("NEXUS0_QUARANTINE") {
        cfg.quarantine_dir = PathBuf::from(v);
    }
    if let Ok(v) = env::var("NEXUS0_DROP_THRESHOLD") {
        cfg.drop_threshold = parse_threshold("NEXUS0_DROP_THRESHOLD", &v)?;
    }
    if let Ok(v) = env::var("NEXUS0_QUARANTINE_THRESHOLD") {
        cfg.quarantine_threshold = parse_threshold("NEXUS0_QUARANTINE_THRESHOLD", &v)?;
    }
    if let Ok(v) = env::var("NEXUS0_MAX_SESSIONS") {
        cfg.max_sessions = parse_sessions("NEXUS0_MAX_SESSIONS", &v)?;
    }
    if let Ok(v) = env::var("NEXUS0_ALLOW_REMOTE") {
        cfg.allow_remote = parse_bool("NEXUS0_ALLOW_REMOTE", &v)?;
    }
    Ok(())
}

fn apply_args<I, S>(cfg: &mut Config, args: I) -> Result<(), ConfigError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let arg = arg.as_ref().to_string();
        match arg.as_str() {
            "--bind" => cfg.bind = take_value("--bind", &mut args)?,
            "--stats" => cfg.stats_path = PathBuf::from(take_value("--stats", &mut args)?),
            "--events" => cfg.events_path = PathBuf::from(take_value("--events", &mut args)?),
            "--quarantine" => {
                cfg.quarantine_dir = PathBuf::from(take_value("--quarantine", &mut args)?)
            }
            "--drop-threshold" => {
                let v = take_value("--drop-threshold", &mut args)?;
                cfg.drop_threshold = parse_threshold("--drop-threshold", &v)?;
            }
            "--quarantine-threshold" => {
                let v = take_value("--quarantine-threshold", &mut args)?;
                cfg.quarantine_threshold = parse_threshold("--quarantine-threshold", &v)?;
            }
            "--max-sessions" => {
                let v = take_value("--max-sessions", &mut args)?;
                cfg.max_sessions = parse_sessions("--max-sessions", &v)?;
            }
            "--allow-remote" => cfg.allow_remote = true,
            "--help" | "-h" => return Err(ConfigError::Help),
            other => {
                return Err(ConfigError::Invalid(format!(
                    "unknown argument {other} (try --help)"
                )));
            }
        }
    }
    Ok(())
}

fn take_value<I, S>(flag: &str, args: &mut I) -> Result<String, ConfigError>
where
    I: Iterator<Item = S>,
    S: AsRef<str>,
{
    let Some(value) = args.next() else {
        return Err(ConfigError::Invalid(format!("{flag} requires a value")));
    };
    let value = value.as_ref();
    if value.starts_with("--") {
        return Err(ConfigError::Invalid(format!("{flag} requires a value")));
    }
    Ok(value.to_string())
}

fn parse_threshold(flag: &str, value: &str) -> Result<f32, ConfigError> {
    let f: f32 = value.parse().map_err(|_| {
        ConfigError::Invalid(format!(
            "{flag} must be a number between 0 and 1, got {value}"
        ))
    })?;
    if !f.is_finite() || !(0.0..=1.0).contains(&f) {
        return Err(ConfigError::Invalid(format!(
            "{flag} must be a number between 0 and 1, got {value}"
        )));
    }
    Ok(f)
}

fn parse_bool(flag: &str, value: &str) -> Result<bool, ConfigError> {
    match value {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => Err(ConfigError::Invalid(format!(
            "{flag} must be true or false, got {value}"
        ))),
    }
}

fn parse_sessions(flag: &str, value: &str) -> Result<usize, ConfigError> {
    let n: usize = value.parse().map_err(|_| {
        ConfigError::Invalid(format!("{flag} must be a positive integer, got {value}"))
    })?;
    if n == 0 {
        return Err(ConfigError::Invalid(format!(
            "{flag} must be a positive integer, got {value}"
        )));
    }
    Ok(n)
}

fn validate(cfg: &Config) -> Result<(), ConfigError> {
    if cfg.quarantine_threshold >= cfg.drop_threshold {
        return Err(ConfigError::Invalid(format!(
            "quarantine threshold ({}) must be below drop threshold ({})",
            cfg.quarantine_threshold, cfg.drop_threshold
        )));
    }
    Ok(())
}

pub fn print_help() {
    eprintln!(
        "NEXUS-0 reflex core\n\
         \n\
         USAGE:\n\
           nexus-0 [--bind ADDR] [--stats PATH] [--events PATH] [--quarantine DIR]\n\
                   [--drop-threshold F] [--quarantine-threshold F] [--max-sessions N]\n\
                   [--allow-remote]\n\
         \n\
         ADDR is a Unix socket path on Unix, or host:port on Windows.\n\
         Scores are heuristic. Default quarantine is 0.80. Default drop is 0.95\n\
         and applies only when the request sets FLAG_DROP_IF_MALICIOUS (0x0004).\n\
         Flags override NEXUS0_BIND, NEXUS0_STATS, NEXUS0_EVENTS, NEXUS0_QUARANTINE,\n\
         NEXUS0_DROP_THRESHOLD, NEXUS0_QUARANTINE_THRESHOLD, NEXUS0_MAX_SESSIONS,\n\
         and NEXUS0_ALLOW_REMOTE. Non-loopback TCP binds require --allow-remote.\n\
         \n\
         Defaults: bind={bind}\n\
                   stats={stats}\n\
                   events={events}\n\
                   quarantine={quarantine}",
        bind = default_bind(),
        stats = default_runtime_path("nexus0.stats").display(),
        events = default_runtime_path("nexus0.events").display(),
        quarantine = default_runtime_path("quarantine").display(),
    );
}

/// Per-user runtime directory. On Unix this is `{temp}/nexus0-{uid}` so the
/// socket is not created directly in a shared temp directory.
pub fn default_runtime_dir() -> PathBuf {
    #[cfg(unix)]
    {
        let uid = unsafe { getuid() };
        env::temp_dir().join(format!("nexus0-{uid}"))
    }
    #[cfg(not(unix))]
    {
        env::temp_dir().join("nexus0")
    }
}

#[cfg(unix)]
extern "C" {
    fn getuid() -> u32;
}

pub fn default_bind() -> String {
    #[cfg(unix)]
    {
        default_runtime_dir()
            .join("nexus0.sock")
            .to_string_lossy()
            .into_owned()
    }
    #[cfg(windows)]
    {
        "127.0.0.1:9800".to_string()
    }
    #[cfg(not(any(unix, windows)))]
    {
        "127.0.0.1:9800".to_string()
    }
}

pub fn default_runtime_path(name: &str) -> PathBuf {
    default_runtime_dir().join(name)
}

pub fn client_bind() -> String {
    env::var("NEXUS0_BIND").unwrap_or_else(|_| default_bind())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_overrides_env_bind() {
        let mut cfg = Config {
            bind: "127.0.0.1:1".to_string(),
            ..Config::default()
        };
        apply_args(&mut cfg, ["--bind", "127.0.0.1:9"]).unwrap();
        assert_eq!(cfg.bind, "127.0.0.1:9");
    }

    #[test]
    fn unknown_argument_is_an_error() {
        let mut cfg = Config::default();
        let err = apply_args(&mut cfg, ["--nope"]).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn missing_flag_value_is_an_error() {
        let mut cfg = Config::default();
        let err = apply_args(&mut cfg, ["--bind"]).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn bad_threshold_is_rejected() {
        let mut cfg = Config::default();
        assert!(apply_args(&mut cfg, ["--drop-threshold", "nope"]).is_err());
        assert!(apply_args(&mut cfg, ["--drop-threshold", "1.5"]).is_err());
    }

    #[test]
    fn quarantine_must_sit_below_drop() {
        let mut cfg = Config::default();
        apply_args(
            &mut cfg,
            ["--drop-threshold", "0.5", "--quarantine-threshold", "0.9"],
        )
        .unwrap();
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn remote_bind_is_opt_in() {
        let mut cfg = Config::default();
        assert!(!cfg.allow_remote);
        apply_args(&mut cfg, ["--allow-remote"]).unwrap();
        assert!(cfg.allow_remote);
    }

    #[test]
    fn help_is_not_an_invalid_argument() {
        let mut cfg = Config::default();
        let err = apply_args(&mut cfg, ["--help"]).unwrap_err();
        assert!(matches!(err, ConfigError::Help));
    }
}
