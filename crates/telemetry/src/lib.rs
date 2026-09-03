use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTelemetry {
    pub hostname: String,
    pub os: String,
    pub agent_version: String,
    pub is_active: bool,
}

pub fn collect_telemetry() -> DeviceTelemetry {
    DeviceTelemetry {
        hostname: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string()),
        os: std::env::consts::OS.to_string(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        is_active: true,
    }
}
