use safeprompt_common::DlpEvent;
use tracing::info;

pub struct AuditLogger;

impl AuditLogger {
    pub fn log_event(event: &DlpEvent) {
        info!(
            "DLP_EVENT [{}]: Action={:?}, App={}, Domain={}, Findings={}",
            event.event_type,
            event.action_taken,
            event.app_name,
            event.domain,
            event.findings.len()
        );
    }
}
