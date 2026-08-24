use serde::Serialize;
pub const DETECTOR_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleId {
    InstructionOverride,
    SystemPromptExtraction,
    SensitiveDataExposure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RuleMetadata {
    pub id: RuleId,
    pub code: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub score: u8,
}

impl RuleId {
    pub fn metadata(self) -> RuleMetadata {
        match self {
            RuleId::InstructionOverride => RuleMetadata {
                id: self,
                code: "AIS001",
                name: "Instruction Override",
                description: "Instruction-override phrase detected",
                score: 40,
            },
            RuleId::SystemPromptExtraction => RuleMetadata {
                id: self,
                code: "AIS002",
                name: "System Prompt Extraction",
                description: "System-prompt extraction attempt detected",
                score: 50,
            },
            RuleId::SensitiveDataExposure => RuleMetadata {
                id: self,
                code: "AIS003",
                name: "Sensitive Data Exposure",
                description: "Sensitive-data exposure attempt detected",
                score: 35,
            },
        }
    }
}
pub fn enabled_rules() -> [RuleMetadata; 3] {
    [
        RuleId::InstructionOverride.metadata(),
        RuleId::SystemPromptExtraction.metadata(),
        RuleId::SensitiveDataExposure.metadata(),
    ]
}
#[cfg(test)]
mod tests {
    use super::{DETECTOR_VERSION, RuleId, enabled_rules};

    #[test]
    fn exposes_stable_rule_metadata() {
        let rules = enabled_rules();

        assert_eq!(DETECTOR_VERSION, "0.1.0");
        assert_eq!(rules.len(), 3);

        assert_eq!(rules[0].id, RuleId::InstructionOverride);
        assert_eq!(rules[0].code, "AIS001");
        assert_eq!(rules[0].score, 40);

        assert_eq!(rules[1].id, RuleId::SystemPromptExtraction);
        assert_eq!(rules[1].code, "AIS002");
        assert_eq!(rules[1].score, 50);

        assert_eq!(rules[2].id, RuleId::SensitiveDataExposure);
        assert_eq!(rules[2].code, "AIS003");
        assert_eq!(rules[2].score, 35);
    }

    #[test]
    fn rule_codes_are_unique() {
        let rules = enabled_rules();

        for (index, rule) in rules.iter().enumerate() {
            for other in rules.iter().skip(index + 1) {
                assert_ne!(rule.code, other.code);
                assert_ne!(rule.id, other.id);
            }
        }
    }
}
