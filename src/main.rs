//! NEXUS-0 reflex core — bind a socket and serve framed binary requests.

fn main() {
    let cfg = match nexus0::Config::from_env_and_args() {
        Ok(cfg) => cfg,
        Err(nexus0::config::ConfigError::Help) => {
            nexus0::config::print_help();
            return;
        }
        Err(nexus0::config::ConfigError::Invalid(msg)) => {
            eprintln!("nexus-0: {msg}");
            std::process::exit(2);
        }
    };
    if let Err(e) = nexus0::ipc::run(cfg) {
        eprintln!("nexus-0: {e}");
        std::process::exit(1);
    }
}
