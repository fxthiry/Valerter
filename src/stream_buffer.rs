//! Safe UTF-8 streaming line buffer.
//!
//! This module handles fragmented UTF-8 characters across TCP chunk boundaries.
//! AD-01: 100% test coverage required for this module.

use crate::error::StreamError;

/// Buffer for safe UTF-8 streaming line reconstruction.
///
/// Handles fragmented UTF-8 characters across TCP chunk boundaries.
/// Accumulates bytes until complete lines are available, ensuring
/// multi-byte characters are never split during decoding.
#[derive(Debug, Default)]
pub struct StreamBuffer {
    buffer: Vec<u8>,
}

impl StreamBuffer {
    /// Create a new empty buffer.
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Push raw bytes into the buffer.
    pub fn push(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
    }

    /// Drain all complete lines from the buffer.
    ///
    /// Returns complete lines (without trailing newlines) that have been
    /// fully received and are valid UTF-8. Incomplete lines or partial
    /// UTF-8 characters remain in the buffer.
    ///
    /// # Errors
    /// Returns `StreamError::Utf8Error` if the buffer contains invalid UTF-8.
    pub fn drain_complete_lines(&mut self) -> Result<Vec<String>, StreamError> {
        let mut lines = Vec::new();

        // Find the last newline position
        if let Some(last_newline) = self.buffer.iter().rposition(|&b| b == b'\n') {
            // Find safe UTF-8 boundary up to and including the last newline
            // Note: safe_end is guaranteed > 0 when there's a newline,
            // because newline (0x0A) is ASCII and always a safe boundary
            let safe_end = find_safe_utf8_boundary(&self.buffer[..=last_newline]);

            // Extract complete portion
            let complete: Vec<u8> = self.buffer.drain(..safe_end).collect();

            // Decode and split into lines
            let text = String::from_utf8(complete)
                .map_err(|e| StreamError::Utf8Error(e.to_string()))?;

            for line in text.lines() {
                lines.push(line.to_string());
            }
        }

        Ok(lines)
    }

    /// Get current buffer size in bytes.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

/// Find the last position in the buffer that ends on a valid UTF-8 boundary.
///
/// This prevents splitting multi-byte characters when draining the buffer.
/// Returns the number of bytes that can be safely decoded as UTF-8.
fn find_safe_utf8_boundary(buffer: &[u8]) -> usize {
    if buffer.is_empty() {
        return 0;
    }

    let len = buffer.len();
    let mut pos = len;

    // Walk backwards to find start of last (potentially incomplete) character
    while pos > 0 {
        let byte = buffer[pos - 1];

        // ASCII byte (0x00-0x7F) - always a complete character, safe boundary
        if byte & 0x80 == 0 {
            return pos;
        }

        // Check if this is a start byte (not a continuation byte)
        // Continuation bytes are 0x80-0xBF (binary: 10xxxxxx)
        if byte & 0xC0 != 0x80 {
            // This is a start byte, determine expected character length
            let char_start = pos - 1;
            let expected_len = if byte & 0xF8 == 0xF0 {
                4 // 11110xxx - 4-byte character
            } else if byte & 0xF0 == 0xE0 {
                3 // 1110xxxx - 3-byte character
            } else if byte & 0xE0 == 0xC0 {
                2 // 110xxxxx - 2-byte character
            } else {
                // Invalid leading byte (0x80-0xBF or 0xF8+), treat as 1 byte
                1
            };

            if char_start + expected_len <= len {
                // Character is complete, include it
                return char_start + expected_len;
            } else {
                // Character is incomplete - boundary is before it
                return char_start;
            }
        }

        pos -= 1;
    }

    // Buffer contains only continuation bytes - invalid UTF-8
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test 4.1: Ligne complete simple ASCII
    #[test]
    fn test_complete_ascii_line() {
        let mut buffer = StreamBuffer::new();
        buffer.push(b"Hello World\n");

        let lines = buffer.drain_complete_lines().unwrap();
        assert_eq!(lines, vec!["Hello World"]);
        assert!(buffer.is_empty());
    }

    // Test 4.2: Ligne complete avec accents français
    #[test]
    fn test_complete_line_with_french_accents() {
        let mut buffer = StreamBuffer::new();
        // "été" contains é (C3 A9) twice
        buffer.push("Café crème été\n".as_bytes());

        let lines = buffer.drain_complete_lines().unwrap();
        assert_eq!(lines, vec!["Café crème été"]);
        assert!(buffer.is_empty());
    }

    // Test 4.3: Emoji 4 octets coupé en 2 chunks
    #[test]
    fn test_emoji_split_in_two_chunks() {
        let mut buffer = StreamBuffer::new();

        // 🚨 = F0 9F 9A A8
        // Chunk 1: "Hello " + first 2 bytes of emoji
        buffer.push(&[0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0xF0, 0x9F]);

        // Should return no complete lines yet (no newline)
        let lines = buffer.drain_complete_lines().unwrap();
        assert!(lines.is_empty());

        // Chunk 2: last 2 bytes of emoji + newline
        buffer.push(&[0x9A, 0xA8, 0x0A]);

        let lines = buffer.drain_complete_lines().unwrap();
        assert_eq!(lines, vec!["Hello 🚨"]);
        assert!(buffer.is_empty());
    }

    // Test 4.4: Emoji coupé en 4 chunks (1 byte chacun)
    #[test]
    fn test_emoji_split_in_four_chunks() {
        let mut buffer = StreamBuffer::new();

        // 🚨 = F0 9F 9A A8, sent byte by byte
        buffer.push(&[0xF0]);
        assert!(buffer.drain_complete_lines().unwrap().is_empty());

        buffer.push(&[0x9F]);
        assert!(buffer.drain_complete_lines().unwrap().is_empty());

        buffer.push(&[0x9A]);
        assert!(buffer.drain_complete_lines().unwrap().is_empty());

        buffer.push(&[0xA8, 0x0A]); // Last byte + newline

        let lines = buffer.drain_complete_lines().unwrap();
        assert_eq!(lines, vec!["🚨"]);
        assert!(buffer.is_empty());
    }

    // Test 4.5: Accent 2 octets coupé entre 2 chunks
    #[test]
    fn test_accent_split_between_chunks() {
        let mut buffer = StreamBuffer::new();

        // é = C3 A9
        // Chunk 1: "Caf" + first byte of é
        buffer.push(&[0x43, 0x61, 0x66, 0xC3]);

        let lines = buffer.drain_complete_lines().unwrap();
        assert!(lines.is_empty()); // No newline yet

        // Chunk 2: second byte of é + newline
        buffer.push(&[0xA9, 0x0A]);

        let lines = buffer.drain_complete_lines().unwrap();
        assert_eq!(lines, vec!["Café"]);
        assert!(buffer.is_empty());
    }

    // Test 4.6: Séquence UTF-8 invalide (byte 0xFF seul)
    #[test]
    fn test_invalid_utf8_sequence() {
        let mut buffer = StreamBuffer::new();

        // 0xFF is never valid in UTF-8
        buffer.push(&[0x48, 0x65, 0x6C, 0x6C, 0x6F, 0xFF, 0x0A]);

        let result = buffer.drain_complete_lines();
        assert!(result.is_err());
        match result {
            Err(StreamError::Utf8Error(msg)) => {
                assert!(msg.contains("invalid"));
            }
            _ => panic!("Expected Utf8Error"),
        }
    }

    // Test 4.7: Buffer vide
    #[test]
    fn test_empty_buffer() {
        let mut buffer = StreamBuffer::new();

        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);

        let lines = buffer.drain_complete_lines().unwrap();
        assert!(lines.is_empty());
    }

    // Test 4.8: Multiple lignes dans un seul chunk
    #[test]
    fn test_multiple_lines_single_chunk() {
        let mut buffer = StreamBuffer::new();
        buffer.push(b"Line 1\nLine 2\nLine 3\n");

        let lines = buffer.drain_complete_lines().unwrap();
        assert_eq!(lines, vec!["Line 1", "Line 2", "Line 3"]);
        assert!(buffer.is_empty());
    }

    // Test 4.9: Ligne sans newline (doit rester dans le buffer)
    #[test]
    fn test_incomplete_line_stays_in_buffer() {
        let mut buffer = StreamBuffer::new();
        buffer.push(b"Incomplete line");

        let lines = buffer.drain_complete_lines().unwrap();
        assert!(lines.is_empty());
        assert_eq!(buffer.len(), 15); // "Incomplete line" = 15 bytes

        // Now add newline
        buffer.push(b"\n");
        let lines = buffer.drain_complete_lines().unwrap();
        assert_eq!(lines, vec!["Incomplete line"]);
        assert!(buffer.is_empty());
    }

    // Test 4.10: Caractère chinois 3 octets coupé
    #[test]
    fn test_chinese_char_split() {
        let mut buffer = StreamBuffer::new();

        // 中 (zhōng) = E4 B8 AD
        // Chunk 1: first byte
        buffer.push(&[0xE4]);
        assert!(buffer.drain_complete_lines().unwrap().is_empty());

        // Chunk 2: second byte
        buffer.push(&[0xB8]);
        assert!(buffer.drain_complete_lines().unwrap().is_empty());

        // Chunk 3: third byte + newline
        buffer.push(&[0xAD, 0x0A]);

        let lines = buffer.drain_complete_lines().unwrap();
        assert_eq!(lines, vec!["中"]);
        assert!(buffer.is_empty());
    }

    // Test 4.11: Mix ASCII + multi-byte dans même ligne
    #[test]
    fn test_mixed_ascii_and_multibyte() {
        let mut buffer = StreamBuffer::new();

        // "Hello 中 🚨 été\n"
        buffer.push("Hello 中 🚨 été\n".as_bytes());

        let lines = buffer.drain_complete_lines().unwrap();
        assert_eq!(lines, vec!["Hello 中 🚨 été"]);
        assert!(buffer.is_empty());
    }

    // Additional test: StreamBuffer::new() creates empty buffer
    #[test]
    fn test_new_buffer_is_empty() {
        let buffer = StreamBuffer::new();
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
    }

    // Additional test: Default trait implementation
    #[test]
    fn test_default_trait() {
        let buffer = StreamBuffer::default();
        assert!(buffer.is_empty());
    }

    // Test find_safe_utf8_boundary with empty buffer
    #[test]
    fn test_safe_boundary_empty() {
        assert_eq!(find_safe_utf8_boundary(&[]), 0);
    }

    // Test find_safe_utf8_boundary with pure ASCII
    #[test]
    fn test_safe_boundary_ascii() {
        assert_eq!(find_safe_utf8_boundary(b"Hello\n"), 6);
    }

    // Test find_safe_utf8_boundary with incomplete 2-byte char
    #[test]
    fn test_safe_boundary_incomplete_2byte() {
        // C3 is start of 2-byte sequence, but missing second byte
        let data = [0x48, 0x65, 0x6C, 0x6C, 0x6F, 0xC3]; // "Hello" + start of é
        assert_eq!(find_safe_utf8_boundary(&data), 5); // Stop before C3
    }

    // Test find_safe_utf8_boundary with incomplete 3-byte char
    #[test]
    fn test_safe_boundary_incomplete_3byte() {
        // E4 B8 is start of 3-byte sequence (中), missing third byte
        let data = [0x48, 0x69, 0xE4, 0xB8]; // "Hi" + incomplete 中
        assert_eq!(find_safe_utf8_boundary(&data), 2); // Stop before E4
    }

    // Test find_safe_utf8_boundary with incomplete 4-byte char
    #[test]
    fn test_safe_boundary_incomplete_4byte() {
        // F0 9F 9A is start of 4-byte emoji, missing last byte
        let data = [0x48, 0x69, 0xF0, 0x9F, 0x9A]; // "Hi" + incomplete 🚨
        assert_eq!(find_safe_utf8_boundary(&data), 2); // Stop before F0
    }

    // Test find_safe_utf8_boundary with complete multi-byte followed by newline
    #[test]
    fn test_safe_boundary_complete_multibyte() {
        // 中 (E4 B8 AD) followed by newline
        let data = [0xE4, 0xB8, 0xAD, 0x0A];
        assert_eq!(find_safe_utf8_boundary(&data), 4); // All bytes safe
    }

    // Test with only continuation bytes (invalid UTF-8)
    #[test]
    fn test_safe_boundary_only_continuation_bytes() {
        // All continuation bytes - should return 0
        let data = [0x80, 0x81, 0x82];
        assert_eq!(find_safe_utf8_boundary(&data), 0);
    }

    // Test consecutive drains
    #[test]
    fn test_consecutive_drains() {
        let mut buffer = StreamBuffer::new();

        buffer.push(b"First\n");
        assert_eq!(
            buffer.drain_complete_lines().unwrap(),
            vec!["First"]
        );

        buffer.push(b"Second\n");
        assert_eq!(
            buffer.drain_complete_lines().unwrap(),
            vec!["Second"]
        );

        buffer.push(b"Third\nFourth\n");
        assert_eq!(
            buffer.drain_complete_lines().unwrap(),
            vec!["Third", "Fourth"]
        );
    }

    // Test partial line followed by complete lines
    #[test]
    fn test_partial_then_complete() {
        let mut buffer = StreamBuffer::new();

        buffer.push(b"Partial");
        assert!(buffer.drain_complete_lines().unwrap().is_empty());

        buffer.push(b" line\nComplete\n");
        let lines = buffer.drain_complete_lines().unwrap();
        assert_eq!(lines, vec!["Partial line", "Complete"]);
    }

    // Test: multiple complete lines followed by incomplete line
    #[test]
    fn test_complete_lines_with_trailing_incomplete() {
        let mut buffer = StreamBuffer::new();

        buffer.push(b"Line1\nLine2\nIncomplete");

        let lines = buffer.drain_complete_lines().unwrap();
        assert_eq!(lines, vec!["Line1", "Line2"]);
        assert_eq!(buffer.len(), 10); // "Incomplete" = 10 bytes remains

        // Now complete the line
        buffer.push(b" data\n");
        let lines = buffer.drain_complete_lines().unwrap();
        assert_eq!(lines, vec!["Incomplete data"]);
        assert!(buffer.is_empty());
    }

    // Test: newline after only continuation bytes returns UTF-8 error
    // because when we try to decode, the continuation bytes are invalid
    #[test]
    fn test_newline_after_continuation_bytes_returns_error() {
        let mut buffer = StreamBuffer::new();

        // Continuation bytes followed by newline
        // The newline is ASCII so safe_end includes it, but decoding fails
        buffer.push(&[0x80, 0x81, 0x0A]);

        let result = buffer.drain_complete_lines();
        assert!(result.is_err());
        match result {
            Err(StreamError::Utf8Error(_)) => {}
            _ => panic!("Expected Utf8Error"),
        }
    }

    // Test: invalid leading byte (0xF8+) which is treated as 1 byte
    #[test]
    fn test_invalid_leading_byte_f8_plus() {
        // 0xF8 is an invalid leading byte (would indicate 5+ byte sequence, not valid in UTF-8)
        let data = [0x48, 0x69, 0xF8]; // "Hi" + invalid leading byte
        // Should treat 0xF8 as 1 byte and return full length
        assert_eq!(find_safe_utf8_boundary(&data), 3);
    }

    // Test: incomplete char followed by newline returns error
    // because incomplete UTF-8 sequences followed by newline are still invalid
    #[test]
    fn test_incomplete_char_before_newline_returns_error() {
        let mut buffer = StreamBuffer::new();

        // Incomplete 3-byte char (E4 B8) followed by newline
        // The newline is ASCII so safe_end includes up to it
        // But decoding E4 B8 0A fails as invalid UTF-8
        buffer.push(&[0xE4, 0xB8, 0x0A]);

        let result = buffer.drain_complete_lines();
        assert!(result.is_err());
        match result {
            Err(StreamError::Utf8Error(_)) => {}
            _ => panic!("Expected Utf8Error"),
        }
    }

    // Test: verify that newline is always a safe boundary
    // This confirms that safe_end is never 0 when there's a newline
    #[test]
    fn test_newline_always_safe_boundary() {
        // Newline (0x0A) is ASCII, so it's always a safe UTF-8 boundary
        // This means safe_end is guaranteed > 0 when there's a newline
        let data = [0x80, 0x81, 0x0A];
        // 0x0A is ASCII (0x0A & 0x80 == 0), so boundary includes it
        assert_eq!(find_safe_utf8_boundary(&data), 3);

        // Even with just a newline
        let data = [0x0A];
        assert_eq!(find_safe_utf8_boundary(&data), 1);
    }
}
