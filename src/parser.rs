//! Log line parsing for VictoriaLogs (regex and JSON extraction).
//!
//! This module extracts fields from VictoriaLogs log lines according to rule
//! configurations. VictoriaLogs sends NDJSON with all fields at root level:
//!
//! ```json
//! {"_time":"2026-01-09T10:00:00Z","_stream":"{}","_msg":"error occurred","hostname":"srv-01"}
//! ```
//!
//! The parser:
//! 1. Parses the complete JSON (all fields accessible at root)
//! 2. If regex configured → applies to `_msg` field
//! 3. If json.fields configured → extracts from root or nested paths
//! 4. Returns enriched JSON ready for minijinja templating
//!
//! # Error Handling (FR20, FR21)
//!
//! Parse errors are expected and should be handled silently (the log is skipped).
//! Use [`record_parse_error`] to log and record metrics for parse failures.

use crate::config::{CompiledParser, JsonParserConfig};
use crate::error::ParseError;
use regex::Regex;
use serde_json::{Map, Value};

/// Record a parse error with logging and metrics (FR20, FR21).
///
/// This function should be called by the pipeline code when parsing fails.
/// It logs the error at the appropriate level and increments the
/// `valerter_parse_errors_total` counter with proper labels.
///
/// # Arguments
///
/// * `rule_name` - The name of the rule that encountered the error
/// * `error` - The parse error that occurred
///
/// # Example
///
/// ```ignore
/// match parser.parse(&line) {
///     Ok(fields) => { /* process */ }
///     Err(e) => {
///         record_parse_error(&rule.name, &e);
///         // Skip this log silently (FR20)
///     }
/// }
/// ```
pub fn record_parse_error(rule_name: &str, error: &ParseError) {
    let error_type = match error {
        ParseError::NoMatch => "regex_no_match",
        ParseError::InvalidJson(_) => "invalid_json",
    };

    // Log at appropriate level (FR20: skip silently, but we can debug/warn)
    match error {
        ParseError::NoMatch => {
            // NoMatch is normal behavior - log at DEBUG level
            tracing::debug!(
                rule_name = %rule_name,
                "Regex did not match, skipping log"
            );
        }
        ParseError::InvalidJson(msg) => {
            // Invalid JSON is unexpected - log at WARN level
            tracing::warn!(
                rule_name = %rule_name,
                error = %msg,
                "Invalid JSON in log"
            );
        }
    }

    // Increment metric (FR21)
    metrics::counter!(
        "valerter_parse_errors_total",
        "rule_name" => rule_name.to_string(),
        "error_type" => error_type
    )
    .increment(1);
}

/// Parser for a single rule, combining VictoriaLogs envelope parsing
/// with optional regex or JSON field extraction.
///
/// # Example
///
/// ```ignore
/// use valerter::parser::RuleParser;
///
/// let parser = RuleParser::new(Some(regex), None);
/// let fields = parser.parse(r#"{"_msg":"192.168.1.1 GET /api",...}"#)?;
/// ```
#[derive(Debug)]
pub struct RuleParser {
    /// Pre-compiled regex pattern (from CompiledRule) - applied to _msg
    regex: Option<Regex>,
    /// JSON fields to extract (dot-notation paths) - from root or _msg
    json_fields: Option<Vec<String>>,
}

impl RuleParser {
    /// Creates a new `RuleParser` from a `CompiledParser`.
    ///
    /// The regex is already pre-compiled by `Config::compile()`.
    pub fn from_compiled(compiled: &CompiledParser) -> Self {
        Self {
            regex: compiled.regex.clone(),
            json_fields: compiled.json.as_ref().map(|j| j.fields.clone()),
        }
    }

    /// Creates a new `RuleParser` with explicit regex and JSON config.
    ///
    /// Useful for testing.
    pub fn new(regex: Option<Regex>, json_config: Option<JsonParserConfig>) -> Self {
        Self {
            regex,
            json_fields: json_config.map(|j| j.fields),
        }
    }

    /// Parse a raw log line from VictoriaLogs.
    ///
    /// VictoriaLogs JSON contains all fields at root level:
    /// - `_time`, `_stream`, `_stream_id`, `_msg` (VictoriaLogs fields)
    /// - Custom fields from the log source (hostname, EventID, etc.)
    ///
    /// The regex applies ONLY to `_msg` (for syslog-style logs).
    /// JSON field extraction works on the root object.
    ///
    /// # Errors
    ///
    /// - `ParseError::InvalidJson` if the line is not valid JSON
    /// - `ParseError::NoMatch` if regex is configured but doesn't match `_msg`
    pub fn parse(&self, line: &str) -> Result<Value, ParseError> {
        // Step 1: Parse the complete JSON - all fields are already at root
        let mut log: Map<String, Value> =
            serde_json::from_str(line).map_err(|e| ParseError::InvalidJson(e.to_string()))?;

        // Step 2: If regex configured, apply to _msg
        if let Some(ref regex) = self.regex {
            let msg = log.get("_msg").and_then(|v| v.as_str()).ok_or_else(|| {
                ParseError::InvalidJson("_msg missing or not a string".to_string())
            })?;

            let extracted = self.parse_regex(regex, msg)?;
            for (key, value) in extracted {
                log.insert(key, value);
            }
        }

        // Step 3: If json.fields configured, extract from root
        // (fields are already at root in VictoriaLogs!)
        if let Some(ref fields) = self.json_fields {
            let root_value = Value::Object(log.clone());
            let extracted = self.extract_json_fields(&root_value, fields);
            for (key, value) in extracted {
                log.insert(key, value);
            }
        }

        // Step 4: Parse nested JSON strings (e.g., StringInserts)
        self.parse_nested_json_strings(&mut log);

        Ok(Value::Object(log))
    }

    /// Extract named groups from regex match.
    fn parse_regex(&self, regex: &Regex, text: &str) -> Result<Map<String, Value>, ParseError> {
        let captures = regex.captures(text).ok_or(ParseError::NoMatch)?;

        let mut fields = Map::new();
        for name in regex.capture_names().flatten() {
            if let Some(m) = captures.name(name) {
                fields.insert(name.to_string(), Value::String(m.as_str().to_string()));
            }
        }
        Ok(fields)
    }

    /// Extract fields from JSON using dot-notation paths.
    ///
    /// Converts `data.server.hostname` to JSON pointer `/data/server/hostname`.
    /// Fields not found in the log are silently ignored (logged at DEBUG level).
    fn extract_json_fields(&self, root: &Value, field_paths: &[String]) -> Map<String, Value> {
        let mut fields = Map::new();
        for path in field_paths {
            // Convert dot-notation to JSON pointer: "data.server" -> "/data/server"
            let pointer = format!("/{}", path.replace('.', "/"));
            if let Some(value) = root.pointer(&pointer) {
                // Use the last segment as field name
                let field_name = path.rsplit('.').next().unwrap_or(path);
                fields.insert(field_name.to_string(), value.clone());
            } else {
                // Log at DEBUG level to help debugging configuration issues
                tracing::debug!(field_path = %path, "JSON field not found in log");
            }
        }
        fields
    }

    /// Parse fields that contain JSON strings (e.g., Windows StringInserts).
    ///
    /// Some log fields arrive as JSON strings instead of arrays/objects.
    /// This method detects and parses them.
    fn parse_nested_json_strings(&self, log: &mut Map<String, Value>) {
        // Known fields that may contain JSON strings
        const JSON_STRING_FIELDS: &[&str] = &["StringInserts"];

        for field_name in JSON_STRING_FIELDS {
            if let Some(Value::String(s)) = log.get(*field_name) {
                // Try to parse as JSON - if it fails, leave as string
                if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                    log.insert((*field_name).to_string(), parsed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================
    // Task 1: VictoriaLogs envelope parsing tests
    // ============================================================

    // Test 6.1: Parse VictoriaLogs envelope with _msg string
    #[test]
    fn parse_victorialogs_envelope_with_msg_string() {
        let parser = RuleParser::new(None, None);
        let line = r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{}","_msg":"error occurred"}"#;

        let result = parser.parse(line).unwrap();
        let obj = result.as_object().unwrap();

        assert_eq!(obj.get("_time").unwrap(), "2026-01-09T10:00:00Z");
        assert_eq!(obj.get("_stream").unwrap(), "{}");
        assert_eq!(obj.get("_msg").unwrap(), "error occurred");
    }

    // Test 6.2: Parse VictoriaLogs envelope with _msg containing JSON object
    #[test]
    fn parse_victorialogs_envelope_with_msg_json_object() {
        let parser = RuleParser::new(None, None);
        // _msg is a string, but its content is JSON-like
        let line = r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{}","_msg":"{\"level\":\"ERROR\",\"message\":\"failed\"}"}"#;

        let result = parser.parse(line).unwrap();
        let obj = result.as_object().unwrap();

        assert_eq!(obj.get("_time").unwrap(), "2026-01-09T10:00:00Z");
        // _msg is still a string (JSON within JSON)
        assert!(obj.get("_msg").unwrap().is_string());
    }

    // Test: Preserve all VictoriaLogs fields
    #[test]
    fn preserve_all_victorialogs_fields() {
        let parser = RuleParser::new(None, None);
        let line = r#"{
            "_time":"2026-01-09T10:00:00Z",
            "_stream":"{hostname=\"srv-01\"}",
            "_stream_id":"00000000000000007e59d624b556563c",
            "_msg":"test message",
            "hostname":"srv-01",
            "severity":"6"
        }"#;

        let result = parser.parse(line).unwrap();
        let obj = result.as_object().unwrap();

        // All fields preserved
        assert!(obj.contains_key("_time"));
        assert!(obj.contains_key("_stream"));
        assert!(obj.contains_key("_stream_id"));
        assert!(obj.contains_key("_msg"));
        assert!(obj.contains_key("hostname"));
        assert!(obj.contains_key("severity"));
    }

    // ============================================================
    // Task 2: Regex parser tests
    // ============================================================

    // Test 6.3: Regex with simple named groups
    #[test]
    fn parse_regex_simple_named_groups() {
        let regex =
            Regex::new(r"(?P<ip>\d+\.\d+\.\d+\.\d+) (?P<method>\w+) (?P<path>/\S+)").unwrap();
        let parser = RuleParser::new(Some(regex), None);

        let line = r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{}","_msg":"192.168.1.1 GET /api/users"}"#;

        let result = parser.parse(line).unwrap();
        let obj = result.as_object().unwrap();

        assert_eq!(obj.get("ip").unwrap(), "192.168.1.1");
        assert_eq!(obj.get("method").unwrap(), "GET");
        assert_eq!(obj.get("path").unwrap(), "/api/users");
        // Original fields preserved
        assert_eq!(obj.get("_msg").unwrap(), "192.168.1.1 GET /api/users");
    }

    // Test 6.4: Regex with multiple named groups (switch syslog style)
    #[test]
    fn parse_regex_multiple_named_groups() {
        let regex = Regex::new(
            r"(?P<switch>PEX-SW-[^:]+).*%(?P<event_type>[A-Z]+-\d+-[A-Z]+):\s*(?P<message>.*)",
        )
        .unwrap();
        let parser = RuleParser::new(Some(regex), None);

        let line = r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{}","_msg":"168672: PEX-SW-ETG3-307: Jan  9 12:08:52.793: %SYS-6-LOGOUT: User backup has exited"}"#;

        let result = parser.parse(line).unwrap();
        let obj = result.as_object().unwrap();

        assert_eq!(obj.get("switch").unwrap(), "PEX-SW-ETG3-307");
        assert_eq!(obj.get("event_type").unwrap(), "SYS-6-LOGOUT");
        assert_eq!(obj.get("message").unwrap(), "User backup has exited");
    }

    // Test 6.5: Regex no match returns ParseError::NoMatch
    #[test]
    fn parse_regex_no_match_returns_error() {
        let regex = Regex::new(r"(?P<error>ERROR:.*)").unwrap();
        let parser = RuleParser::new(Some(regex), None);

        let line = r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{}","_msg":"INFO: all good"}"#;

        let result = parser.parse(line);
        assert!(matches!(result, Err(ParseError::NoMatch)));
    }

    // ============================================================
    // Task 3: JSON field extraction tests
    // ============================================================

    // Test 6.6: JSON field extraction simple (root level)
    #[test]
    fn parse_json_field_simple() {
        let json_config = JsonParserConfig {
            fields: vec!["hostname".to_string(), "severity".to_string()],
        };
        let parser = RuleParser::new(None, Some(json_config));

        let line = r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{}","_msg":"test","hostname":"srv-01","severity":"6"}"#;

        let result = parser.parse(line).unwrap();
        let obj = result.as_object().unwrap();

        assert_eq!(obj.get("hostname").unwrap(), "srv-01");
        assert_eq!(obj.get("severity").unwrap(), "6");
    }

    // Test 6.7: JSON field extraction nested (dot notation)
    #[test]
    fn parse_json_field_nested() {
        let json_config = JsonParserConfig {
            fields: vec!["data.server.hostname".to_string()],
        };
        let parser = RuleParser::new(None, Some(json_config));

        let line = r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{}","_msg":"test","data":{"server":{"hostname":"srv-01"}}}"#;

        let result = parser.parse(line).unwrap();
        let obj = result.as_object().unwrap();

        // Extracted as "hostname" (last segment)
        assert_eq!(obj.get("hostname").unwrap(), "srv-01");
    }

    // Test 6.8: JSON field extraction deeply nested (3+ levels)
    #[test]
    fn parse_json_field_deeply_nested() {
        let json_config = JsonParserConfig {
            fields: vec!["metadata.labels.app.version".to_string()],
        };
        let parser = RuleParser::new(None, Some(json_config));

        let line = r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{}","_msg":"test","metadata":{"labels":{"app":{"version":"1.2.3"}}}}"#;

        let result = parser.parse(line).unwrap();
        let obj = result.as_object().unwrap();

        assert_eq!(obj.get("version").unwrap(), "1.2.3");
    }

    // Test 6.9: Invalid JSON returns ParseError::InvalidJson
    #[test]
    fn parse_invalid_json_returns_error() {
        let parser = RuleParser::new(None, None);
        let line = "not valid json at all";

        let result = parser.parse(line);
        assert!(matches!(result, Err(ParseError::InvalidJson(_))));
    }

    // ============================================================
    // Task 4: Pipeline tests
    // ============================================================

    // Test 6.10: Complete pipeline - VL line to extracted fields
    #[test]
    fn parse_complete_pipeline() {
        let regex = Regex::new(r"(?P<level>\w+): (?P<message>.*)").unwrap();
        let parser = RuleParser::new(Some(regex), None);

        let line = r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{app=\"test\"}","_msg":"ERROR: connection failed","hostname":"srv-01"}"#;

        let result = parser.parse(line).unwrap();
        let obj = result.as_object().unwrap();

        // VictoriaLogs fields preserved
        assert_eq!(obj.get("_time").unwrap(), "2026-01-09T10:00:00Z");
        assert_eq!(obj.get("_stream").unwrap(), "{app=\"test\"}");
        assert_eq!(obj.get("_msg").unwrap(), "ERROR: connection failed");

        // Root fields preserved
        assert_eq!(obj.get("hostname").unwrap(), "srv-01");

        // Regex extracted fields added
        assert_eq!(obj.get("level").unwrap(), "ERROR");
        assert_eq!(obj.get("message").unwrap(), "connection failed");
    }

    // Test 6.11: Preservation of VictoriaLogs fields with extraction
    #[test]
    fn parse_preserves_vl_fields_with_extraction() {
        let json_config = JsonParserConfig {
            fields: vec!["client_ip".to_string()],
        };
        let parser = RuleParser::new(None, Some(json_config));

        let line = r#"{
            "_time":"2026-01-09T10:00:00Z",
            "_stream":"{group=\"dns\"}",
            "_msg":"query processed",
            "client_ip":"10.255.40.249"
        }"#;

        let result = parser.parse(line).unwrap();
        let obj = result.as_object().unwrap();

        // VL fields preserved
        assert!(obj.contains_key("_time"));
        assert!(obj.contains_key("_stream"));
        assert!(obj.contains_key("_msg"));

        // Extracted field available
        assert_eq!(obj.get("client_ip").unwrap(), "10.255.40.249");
    }

    // ============================================================
    // Additional edge case tests
    // ============================================================

    // Test: StringInserts JSON string parsing (Windows events)
    #[test]
    fn parse_string_inserts_json_string() {
        let parser = RuleParser::new(None, None);
        let line = r#"{
            "_time":"2026-01-09T10:00:00Z",
            "_stream":"{}",
            "_msg":"Logoff",
            "EventID":"4634",
            "StringInserts":"[\"S-1-5-21\",\"user\",\"DOMAIN\",\"0x123\",3]"
        }"#;

        let result = parser.parse(line).unwrap();
        let obj = result.as_object().unwrap();

        // StringInserts should be parsed as array, not string
        let inserts = obj.get("StringInserts").unwrap();
        assert!(
            inserts.is_array(),
            "StringInserts should be parsed as array"
        );
        let arr = inserts.as_array().unwrap();
        assert_eq!(arr.len(), 5);
        assert_eq!(arr[0], "S-1-5-21");
        assert_eq!(arr[1], "user");
    }

    // Test: Missing _msg with regex returns error
    #[test]
    fn parse_missing_msg_with_regex_returns_error() {
        let regex = Regex::new(r"(?P<level>\w+)").unwrap();
        let parser = RuleParser::new(Some(regex), None);

        let line = r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{}"}"#;

        let result = parser.parse(line);
        assert!(matches!(result, Err(ParseError::InvalidJson(_))));
    }

    // Test: Empty regex captures nothing extra
    #[test]
    fn parse_regex_without_named_groups() {
        let regex = Regex::new(r"ERROR").unwrap();
        let parser = RuleParser::new(Some(regex), None);

        let line = r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{}","_msg":"ERROR occurred"}"#;

        let result = parser.parse(line).unwrap();
        let obj = result.as_object().unwrap();

        // Should have original fields, no extra extractions
        assert!(obj.contains_key("_time"));
        assert!(obj.contains_key("_msg"));
        // No named groups = nothing added beyond VL fields
        assert_eq!(obj.len(), 3);
    }

    // Test: JSON field not found - silently ignored
    #[test]
    fn parse_json_field_not_found_silently_ignored() {
        let json_config = JsonParserConfig {
            fields: vec!["nonexistent.field".to_string()],
        };
        let parser = RuleParser::new(None, Some(json_config));

        let line = r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{}","_msg":"test"}"#;

        let result = parser.parse(line).unwrap();
        let obj = result.as_object().unwrap();

        // Should not fail, just not have the field
        assert!(!obj.contains_key("field"));
        assert!(!obj.contains_key("nonexistent"));
    }

    // Test: from_compiled constructor
    #[test]
    fn from_compiled_creates_parser() {
        let compiled = CompiledParser {
            regex: Some(Regex::new(r"(?P<level>\w+)").unwrap()),
            json: Some(JsonParserConfig {
                fields: vec!["hostname".to_string()],
            }),
        };

        let parser = RuleParser::from_compiled(&compiled);

        assert!(parser.regex.is_some());
        assert!(parser.json_fields.is_some());
        assert_eq!(parser.json_fields.as_ref().unwrap().len(), 1);
    }

    // ============================================================
    // Task 5: Error handling and metrics tests
    // ============================================================

    // Test: record_parse_error does not panic for NoMatch
    #[test]
    fn record_parse_error_no_match_does_not_panic() {
        let error = ParseError::NoMatch;
        // Should not panic
        super::record_parse_error("test_rule", &error);
    }

    // Test: record_parse_error does not panic for InvalidJson
    #[test]
    fn record_parse_error_invalid_json_does_not_panic() {
        let error = ParseError::InvalidJson("unexpected token".to_string());
        // Should not panic
        super::record_parse_error("test_rule", &error);
    }
}
