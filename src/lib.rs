//! NEXUS-0: non-autoregressive reflex engine and zero-dependency router.
//!
//! One forward pass over a raw byte payload produces extract spans, in-place
//! redaction, a routing decision, and entropy scores. The decision head is a
//! fixed heuristic network blended with pattern hits. It does not generate text.

pub mod client;
pub mod config;
pub mod engine;
pub mod features;
pub mod ipc;
pub mod model;
pub mod patterns;
pub mod schema;
pub mod seen;
pub mod sketch;
pub mod telemetry;
pub mod tools;

pub use config::Config;
pub use engine::{evaluate, evaluate_in_place, kit, ReflexEngine};
pub use schema::{
    EntityKind, FormatKind, Opcode, Request, Response, RouteAction, Span, ToolReport,
};
pub use telemetry::{Telemetry, TELEMETRY_BYTES};
pub use tools::{const_eq, http_body, http_headers, near_dup, utf8_prefix};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MAGIC: [u8; 4] = *b"NX0\0";
pub const PROTOCOL_VERSION: u8 = 1;
