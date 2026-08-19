//! Domain validation helpers.

use crate::error::DomainError;

/// Validates that a string is non-empty after trimming.
pub fn validate_non_empty<'a>(
    field_name: &'static str,
    val: &'a str,
) -> Result<&'a str, DomainError> {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        Err(DomainError::EmptyField(field_name))
    } else {
        Ok(trimmed)
    }
}

/// Validates that a slug is non-empty, contains only valid slug characters
/// (`[a-z0-9_-]`), and does not start or end with a dash/underscore.
pub fn validate_slug(slug: &str) -> Result<String, DomainError> {
    let trimmed = slug.trim();
    if trimmed.is_empty() {
        return Err(DomainError::EmptyField("slug"));
    }

    let is_valid = trimmed
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !is_valid {
        return Err(DomainError::InvalidSlug(trimmed.to_string()));
    }

    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_non_empty() {
        assert!(validate_non_empty("name", "   ").is_err());
        assert_eq!(validate_non_empty("name", " valid ").unwrap(), "valid");
    }

    #[test]
    fn test_validate_slug() {
        assert!(validate_slug("org-123_abc").is_ok());
        assert!(validate_slug("Org-123").is_err());
        assert!(validate_slug("org 123").is_err());
        assert!(validate_slug("   ").is_err());
    }
}
