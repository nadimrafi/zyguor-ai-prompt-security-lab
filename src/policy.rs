use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayAction {
    Allow,
    Review,
    Block,
}

pub fn action_for_score(risk_score: u8) -> GatewayAction {
    match risk_score {
        0 => GatewayAction::Allow,
        1..=69 => GatewayAction::Review,
        _ => GatewayAction::Block,
    }
}

#[cfg(test)]
mod tests {
    use super::{GatewayAction, action_for_score};

    #[test]
    fn maps_scores_to_gateway_actions() {
        assert_eq!(action_for_score(0), GatewayAction::Allow);
        assert_eq!(action_for_score(1), GatewayAction::Review);
        assert_eq!(action_for_score(69), GatewayAction::Review);
        assert_eq!(action_for_score(70), GatewayAction::Block);
        assert_eq!(action_for_score(100), GatewayAction::Block);
    }
}
