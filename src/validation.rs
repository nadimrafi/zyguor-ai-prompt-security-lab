pub const MAX_PROMPT_CHARACTERS: usize = 4_000;

#[derive(Debug, PartialEq, Eq)]
pub enum PromptValidationError {
    Empty,
    TooLong { actual: usize, maximum: usize },
}

pub fn validate_prompt(prompt: &str) -> Result<(), PromptValidationError> {
    if prompt.trim().is_empty() {
        return Err(PromptValidationError::Empty);
    }

    let character_count = prompt.chars().count();

    if character_count > MAX_PROMPT_CHARACTERS {
        return Err(PromptValidationError::TooLong {
            actual: character_count,
            maximum: MAX_PROMPT_CHARACTERS,
        });
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::{MAX_PROMPT_CHARACTERS, PromptValidationError, validate_prompt};

    #[test]
    fn rejects_empty_prompt() {
        assert_eq!(validate_prompt(""), Err(PromptValidationError::Empty));
    }

    #[test]
    fn rejects_whitespace_only_prompt() {
        assert_eq!(
            validate_prompt("   \n\t"),
            Err(PromptValidationError::Empty)
        );
    }

    #[test]
    fn accepts_prompt_at_character_limit() {
        let prompt = "a".repeat(MAX_PROMPT_CHARACTERS);

        assert_eq!(validate_prompt(&prompt), Ok(()));
    }

    #[test]
    fn rejects_prompt_above_character_limit() {
        let prompt = "a".repeat(MAX_PROMPT_CHARACTERS + 1);

        assert_eq!(
            validate_prompt(&prompt),
            Err(PromptValidationError::TooLong {
                actual: MAX_PROMPT_CHARACTERS + 1,
                maximum: MAX_PROMPT_CHARACTERS,
            })
        );
    }
}
