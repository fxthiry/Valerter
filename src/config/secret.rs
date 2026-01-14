//! Secret string wrapper that never appears in logs.

use serde::Deserialize;

/// Wrapper for secrets that never appears in logs (NFR9).
///
/// This type ensures that sensitive values like webhook URLs are never
/// accidentally logged or displayed. The `Debug` and `Display` implementations
/// always show `[REDACTED]` instead of the actual value.
///
/// # Example
///
/// ```
/// use valerter::config::SecretString;
///
/// let secret = SecretString::new("my-secret-webhook".to_string());
/// assert_eq!(format!("{:?}", secret), "[REDACTED]");
/// assert_eq!(secret.expose(), "my-secret-webhook");
/// ```
#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
    /// Creates a new `SecretString` from a regular `String`.
    ///
    /// The input value will be stored internally but never exposed
    /// through `Debug` or `Display` implementations.
    pub fn new(s: String) -> Self {
        SecretString(s)
    }

    /// Exposes the underlying secret value.
    ///
    /// # Security Warning
    ///
    /// Use with care - never pass the result to logging functions
    /// or any output that could be visible to unauthorized users.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl std::fmt::Display for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(SecretString::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_string_redacts_in_debug_and_display() {
        let secret = SecretString::new("super-secret-webhook".to_string());

        let debug_output = format!("{:?}", secret);
        assert!(!debug_output.contains("super-secret-webhook"));
        assert!(debug_output.contains("[REDACTED]"));

        let display_output = format!("{}", secret);
        assert!(!display_output.contains("super-secret-webhook"));
        assert!(display_output.contains("[REDACTED]"));

        assert_eq!(secret.expose(), "super-secret-webhook");
    }

    #[test]
    fn security_audit_no_secrets_leaked_in_any_format() {
        let webhook_secret =
            SecretString::new("https://mattermost.example.com/hooks/abc123xyz".to_string());
        let token_secret =
            SecretString::new("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9".to_string());

        let representations = vec![
            format!("{:?}", webhook_secret),
            format!("{}", webhook_secret),
            format!("{:?}", token_secret),
            format!("{}", token_secret),
            format!("{:?}", Some(&webhook_secret)),
            format!("{:?}", vec![&webhook_secret]),
        ];

        let forbidden_patterns = [
            "hooks/",
            "abc123xyz",
            "Bearer",
            "eyJ",
            "mattermost.example.com",
        ];

        for repr in &representations {
            for pattern in &forbidden_patterns {
                assert!(
                    !repr.contains(pattern),
                    "SECURITY VIOLATION: Found '{}' in output: {}",
                    pattern,
                    repr
                );
            }
        }
    }
}
