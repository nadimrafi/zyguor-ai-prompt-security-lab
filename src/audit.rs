use tracing::info;
use uuid::Uuid;

use crate::policy::GatewayAction;

#[derive(Debug)]
pub struct AuditEvent {
    pub request_id: Uuid,
    pub prompt_length: usize,
    pub risk_score: u8,
    pub verdict: &'static str,
    pub action: GatewayAction,
    pub finding_count: usize,
}

pub fn record(event: &AuditEvent) {
    let action = match event.action {
        GatewayAction::Allow => "allow",
        GatewayAction::Review => "review",
        GatewayAction::Block => "block",
    };

    info!(
        event = "prompt_analysis_completed",
        request_id = %event.request_id,
        prompt_length = event.prompt_length,
        risk_score = event.risk_score,
        verdict = event.verdict,
        action,
        finding_count = event.finding_count,
    );
}
