use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct ApiKey {
    value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyConfigError {
    Empty,
}

impl ApiKey {
    pub fn new(value: String) -> Result<Self, ApiKeyConfigError> {
        if value.trim().is_empty() {
            return Err(ApiKeyConfigError::Empty);
        }

        Ok(Self { value })
    }

    pub fn matches(&self, candidate: &str) -> bool {
        bool::from(self.value.as_bytes().ct_eq(candidate.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{ApiKey, ApiKeyConfigError};

    #[test]
    fn accepts_matching_api_key() {
        let key = ApiKey::new("test-secret-key".to_string()).expect("test key is valid");

        assert!(key.matches("test-secret-key"));
    }

    #[test]
    fn rejects_incorrect_api_key() {
        let key = ApiKey::new("test-secret-key".to_string()).expect("test key is valid");

        assert!(!key.matches("wrong-key"));
    }

    #[test]
    fn rejects_empty_configured_key() {
        assert!(matches!(
            ApiKey::new("   ".to_string()),
            Err(ApiKeyConfigError::Empty)
        ));
    }
}
