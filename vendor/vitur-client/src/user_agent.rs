use std::env::consts::{ARCH, OS};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const SECONDARY_AGENT: Option<&str> = option_env!("VITUR_SECONDARY_USER_AGENT");

pub fn get_user_agent() -> String {
    format!(
        "vitur-client/{VERSION} ({OS} {ARCH}{})",
        SECONDARY_AGENT.map(|x| format!(" {x}")).unwrap_or_default()
    )
}
