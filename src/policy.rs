use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayAction {
    Allow,
    Review,
    Block,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyConfig {
    review_threshold: u8,
    block_threshold: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyConfigError {
    ReviewThresholdMustBePositive,
    ReviewThresholdMustBeBelowBlockThreshold,
    BlockThresholdCannotExceedOneHundred,
}

impl PolicyConfig {
    pub fn new(review_threshold: u8, block_threshold: u8) -> Result<Self, PolicyConfigError> {
        if review_threshold == 0 {
            return Err(PolicyConfigError::ReviewThresholdMustBePositive);
        }

        if block_threshold > 100 {
            return Err(PolicyConfigError::BlockThresholdCannotExceedOneHundred);
        }

        if review_threshold >= block_threshold {
            return Err(PolicyConfigError::ReviewThresholdMustBeBelowBlockThreshold);
        }

        Ok(Self {
            review_threshold,
            block_threshold,
        })
    }

    pub fn action_for_score(self, risk_score: u8) -> GatewayAction {
        if risk_score < self.review_threshold {
            GatewayAction::Allow
        } else if risk_score < self.block_threshold {
            GatewayAction::Review
        } else {
            GatewayAction::Block
        }
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            review_threshold: 1,
            block_threshold: 70,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{GatewayAction, PolicyConfig, PolicyConfigError};
    #[test]
    fn maps_scores_to_gateway_actions() {
        let policy = PolicyConfig::default();

        assert_eq!(policy.action_for_score(0), GatewayAction::Allow);
        assert_eq!(policy.action_for_score(1), GatewayAction::Review);
        assert_eq!(policy.action_for_score(69), GatewayAction::Review);
        assert_eq!(policy.action_for_score(70), GatewayAction::Block);
        assert_eq!(policy.action_for_score(100), GatewayAction::Block);
    }
    #[test]
    fn applies_custom_policy_thresholds() {
        let policy = PolicyConfig::new(20, 80).expect("20 and 80 are valid policy thresholds");

        assert_eq!(policy.action_for_score(19), GatewayAction::Allow);
        assert_eq!(policy.action_for_score(20), GatewayAction::Review);
        assert_eq!(policy.action_for_score(79), GatewayAction::Review);
        assert_eq!(policy.action_for_score(80), GatewayAction::Block);
    }

    #[test]
    fn rejects_invalid_policy_thresholds() {
        assert_eq!(
            PolicyConfig::new(0, 70),
            Err(PolicyConfigError::ReviewThresholdMustBePositive)
        );

        assert_eq!(
            PolicyConfig::new(70, 70),
            Err(PolicyConfigError::ReviewThresholdMustBeBelowBlockThreshold)
        );

        assert_eq!(
            PolicyConfig::new(10, 101),
            Err(PolicyConfigError::BlockThresholdCannotExceedOneHundred)
        );
    }
}
