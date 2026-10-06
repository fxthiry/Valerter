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

/// Returns a form of `url` that is safe to print.
///
/// User info is replaced by `***`, the query string by `***` and the fragment
/// is dropped. A URL with none of these parts is returned unchanged (no
/// normalization), and a string that cannot be parsed yields `<invalid URL>`.
///
/// # Example
///
/// ```
/// use valerter::config::redact_url;
///
/// assert_eq!(redact_url("http://localhost:9428"), "http://localhost:9428");
/// assert_eq!(
///     redact_url("http://user:pass@vl:9428?token=abc"),
///     "http://***@vl:9428/?***"
/// );
/// ```
pub fn redact_url(url: &str) -> String {
    let Ok(mut parsed) = reqwest::Url::parse(url) else {
        return "<invalid URL>".to_string();
    };

    let has_userinfo = !parsed.username().is_empty() || parsed.password().is_some();
    let has_query = parsed.query().is_some();
    let has_fragment = parsed.fragment().is_some();

    if !has_userinfo && !has_query && !has_fragment {
        return url.to_string();
    }

    if has_userinfo && (parsed.set_username("***").is_err() || parsed.set_password(None).is_err()) {
        return "<invalid URL>".to_string();
    }
    if has_query {
        parsed.set_query(Some("***"));
    }
    parsed.set_fragment(None);
    parsed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_url_keeps_plain_url_unchanged() {
        assert_eq!(redact_url("http://localhost:9428"), "http://localhost:9428");
        assert_eq!(
            redact_url("https://vl.example.com:9428/prefix"),
            "https://vl.example.com:9428/prefix"
        );
    }

    #[test]
    fn redact_url_masks_credentials_and_query() {
        let out = redact_url("http://u:p@vl:9428?token=x");
        assert_eq!(out, "http://***@vl:9428/?***");
        assert!(!out.contains("u:"));
        assert!(!out.contains(":p@"));
        assert!(!out.contains("token="));
    }

    #[test]
    fn redact_url_masks_user_without_password() {
        let out = redact_url("http://alice@vl:9428");
        assert_eq!(out, "http://***@vl:9428/");
        assert!(!out.contains("alice"));
    }

    #[test]
    fn redact_url_masks_password_without_user() {
        let out = redact_url("http://:hunter2@vl:9428");
        assert_eq!(out, "http://***@vl:9428/");
        assert!(!out.contains("hunter2"));
    }

    #[test]
    fn redact_url_masks_query_only() {
        let out = redact_url("http://vl:9428/select?token=abc&x=1");
        assert_eq!(out, "http://vl:9428/select?***");
        assert!(!out.contains("token="));
        assert!(!out.contains("abc"));
    }

    #[test]
    fn redact_url_drops_fragment_only() {
        let out = redact_url("http://vl:9428#secret-frag");
        assert_eq!(out, "http://vl:9428/");
        assert!(!out.contains("secret-frag"));
    }

    #[test]
    fn redact_url_reports_unparsable_input() {
        assert_eq!(redact_url("not a url with s3cret"), "<invalid URL>");
    }

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
