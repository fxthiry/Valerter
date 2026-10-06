//! Safe UTF-8 streaming line buffer.
//!
//! This module splits the raw tail byte stream into lines across TCP chunk
//! boundaries. Each complete line is decoded on its own: splitting on `\n`
//! (0x0A) is always safe in UTF-8 because that byte never appears inside a
//! multi-byte sequence, so a character cut by a chunk boundary simply stays in
//! the pending fragment until the rest of its line arrives.
//!
//! AD-01: 100% test coverage required for this module.

/// Maximum size for a single log line (1MB), counted in bytes before the
/// terminating `\n` (a trailing `\r` included).
/// Lines exceeding this are discarded to prevent OOM.
pub const MAX_LINE_SIZE: usize = 1024 * 1024;

/// Result of feeding one network chunk to a [`StreamBuffer`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ChunkOutcome {
    /// Valid, non-empty lines completed by this chunk, in stream order.
    pub lines: Vec<String>,
    /// Number of complete lines dropped because they are not valid UTF-8.
    pub invalid_utf8: usize,
    /// One entry per oversized line detected in this chunk (observed size in bytes).
    pub oversized: Vec<usize>,
}

/// Buffer for safe UTF-8 streaming line reconstruction.
///
/// Holds the pending (not yet terminated) line, never more than
/// [`MAX_LINE_SIZE`] bytes. Once a line exceeds the limit, its bytes are
/// dropped and everything up to the next `\n` is skipped (`discarding`), so
/// no truncated fragment of it is ever emitted.
#[derive(Debug, Default)]
pub struct StreamBuffer {
    buffer: Vec<u8>,
    discarding: bool,
}

impl StreamBuffer {
    /// Create a new empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one network chunk and return the lines it completes.
    ///
    /// Empty lines are skipped and a trailing `\r` is stripped. A line that is
    /// not valid UTF-8 is dropped alone (counted in `invalid_utf8`); the other
    /// lines of the chunk and the pending fragment are kept.
    pub fn process_chunk(&mut self, chunk: &[u8]) -> ChunkOutcome {
        let mut outcome = ChunkOutcome::default();
        let mut rest = chunk;

        if self.discarding {
            match rest.iter().position(|&b| b == b'\n') {
                None => return outcome,
                Some(pos) => {
                    rest = &rest[pos + 1..];
                    self.discarding = false;
                }
            }
        }

        while let Some(pos) = rest.iter().position(|&b| b == b'\n') {
            let segment = &rest[..pos];
            rest = &rest[pos + 1..];

            let line_len = self.buffer.len() + segment.len();
            if line_len > MAX_LINE_SIZE {
                self.buffer.clear();
                outcome.oversized.push(line_len);
                continue;
            }

            if self.buffer.is_empty() {
                decode_line(segment, &mut outcome);
            } else {
                self.buffer.extend_from_slice(segment);
                decode_line(&self.buffer, &mut outcome);
                self.buffer.clear();
            }
        }

        if !rest.is_empty() {
            let pending = self.buffer.len() + rest.len();
            if pending > MAX_LINE_SIZE {
                self.buffer.clear();
                outcome.oversized.push(pending);
                self.discarding = true;
            } else {
                self.buffer.extend_from_slice(rest);
            }
        }

        outcome
    }

    /// Discard any buffered partial line and leave the discarding state (used
    /// when a connection is replaced, so a fragment from the old stream is
    /// never glued to the new one).
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.discarding = false;
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

/// Decode one complete line (without its `\n`) into `outcome`.
fn decode_line(raw: &[u8], outcome: &mut ChunkOutcome) {
    let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
    if raw.is_empty() {
        return;
    }
    match std::str::from_utf8(raw) {
        Ok(line) => outcome.lines.push(line.to_owned()),
        Err(_) => outcome.invalid_utf8 += 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines_of(outcome: ChunkOutcome) -> Vec<String> {
        assert_eq!(outcome.invalid_utf8, 0);
        assert!(outcome.oversized.is_empty());
        outcome.lines
    }

    // Test 4.1: Ligne complete simple ASCII
    #[test]
    fn test_complete_ascii_line() {
        let mut buffer = StreamBuffer::new();
        let lines = lines_of(buffer.process_chunk(b"Hello World\n"));
        assert_eq!(lines, vec!["Hello World"]);
        assert!(buffer.is_empty());
    }

    // Test 4.2: Ligne complete avec accents français
    #[test]
    fn test_complete_line_with_french_accents() {
        let mut buffer = StreamBuffer::new();
        let lines = lines_of(buffer.process_chunk("Café crème été\n".as_bytes()));
        assert_eq!(lines, vec!["Café crème été"]);
        assert!(buffer.is_empty());
    }

    // Test 4.3: Emoji 4 octets coupé en 2 chunks
    #[test]
    fn test_emoji_split_in_two_chunks() {
        let mut buffer = StreamBuffer::new();

        // 🚨 = F0 9F 9A A8
        // Chunk 1: "Hello " + first 2 bytes of emoji
        let outcome = buffer.process_chunk(&[0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0xF0, 0x9F]);
        assert!(lines_of(outcome).is_empty());

        // Chunk 2: last 2 bytes of emoji + newline
        let lines = lines_of(buffer.process_chunk(&[0x9A, 0xA8, 0x0A]));
        assert_eq!(lines, vec!["Hello 🚨"]);
        assert!(buffer.is_empty());
    }

    // Test 4.4: Emoji coupé en 4 chunks (1 byte chacun)
    #[test]
    fn test_emoji_split_in_four_chunks() {
        let mut buffer = StreamBuffer::new();

        // 🚨 = F0 9F 9A A8, sent byte by byte
        assert!(lines_of(buffer.process_chunk(&[0xF0])).is_empty());
        assert!(lines_of(buffer.process_chunk(&[0x9F])).is_empty());
        assert!(lines_of(buffer.process_chunk(&[0x9A])).is_empty());

        let lines = lines_of(buffer.process_chunk(&[0xA8, 0x0A])); // Last byte + newline
        assert_eq!(lines, vec!["🚨"]);
        assert!(buffer.is_empty());
    }

    // Test 4.5: Accent 2 octets coupé entre 2 chunks
    #[test]
    fn test_accent_split_between_chunks() {
        let mut buffer = StreamBuffer::new();

        // é = C3 A9
        // Chunk 1: "Caf" + first byte of é
        assert!(lines_of(buffer.process_chunk(&[0x43, 0x61, 0x66, 0xC3])).is_empty());

        // Chunk 2: second byte of é + newline
        let lines = lines_of(buffer.process_chunk(&[0xA9, 0x0A]));
        assert_eq!(lines, vec!["Café"]);
        assert!(buffer.is_empty());
    }

    // Test 4.6: Séquence UTF-8 invalide (byte 0xFF seul)
    #[test]
    fn test_invalid_utf8_sequence() {
        let mut buffer = StreamBuffer::new();

        // 0xFF is never valid in UTF-8
        let outcome = buffer.process_chunk(&[0x48, 0x65, 0x6C, 0x6C, 0x6F, 0xFF, 0x0A]);
        assert!(outcome.lines.is_empty());
        assert_eq!(outcome.invalid_utf8, 1);
        assert!(buffer.is_empty());
    }

    // Test 4.7: Buffer vide
    #[test]
    fn test_empty_buffer() {
        let mut buffer = StreamBuffer::new();

        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);

        assert_eq!(buffer.process_chunk(b""), ChunkOutcome::default());
    }

    // Test 4.8: Multiple lignes dans un seul chunk
    #[test]
    fn test_multiple_lines_single_chunk() {
        let mut buffer = StreamBuffer::new();
        let lines = lines_of(buffer.process_chunk(b"Line 1\nLine 2\nLine 3\n"));
        assert_eq!(lines, vec!["Line 1", "Line 2", "Line 3"]);
        assert!(buffer.is_empty());
    }

    // Test 4.9: Ligne sans newline (doit rester dans le buffer)
    #[test]
    fn test_incomplete_line_stays_in_buffer() {
        let mut buffer = StreamBuffer::new();
        assert!(lines_of(buffer.process_chunk(b"Incomplete line")).is_empty());
        assert_eq!(buffer.len(), 15); // "Incomplete line" = 15 bytes

        // Now add newline
        let lines = lines_of(buffer.process_chunk(b"\n"));
        assert_eq!(lines, vec!["Incomplete line"]);
        assert!(buffer.is_empty());
    }

    // Test 4.10: Caractère chinois 3 octets coupé
    #[test]
    fn test_chinese_char_split() {
        let mut buffer = StreamBuffer::new();

        // 中 (zhōng) = E4 B8 AD
        assert!(lines_of(buffer.process_chunk(&[0xE4])).is_empty());
        assert!(lines_of(buffer.process_chunk(&[0xB8])).is_empty());

        // Chunk 3: third byte + newline
        let lines = lines_of(buffer.process_chunk(&[0xAD, 0x0A]));
        assert_eq!(lines, vec!["中"]);
        assert!(buffer.is_empty());
    }

    // Test 4.11: Mix ASCII + multi-byte dans même ligne
    #[test]
    fn test_mixed_ascii_and_multibyte() {
        let mut buffer = StreamBuffer::new();
        let lines = lines_of(buffer.process_chunk("Hello 中 🚨 été\n".as_bytes()));
        assert_eq!(lines, vec!["Hello 中 🚨 été"]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_new_buffer_is_empty() {
        let buffer = StreamBuffer::new();
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
        assert!(!buffer.discarding);
    }

    #[test]
    fn test_default_trait() {
        let buffer = StreamBuffer::default();
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_consecutive_chunks() {
        let mut buffer = StreamBuffer::new();

        assert_eq!(lines_of(buffer.process_chunk(b"First\n")), vec!["First"]);
        assert_eq!(lines_of(buffer.process_chunk(b"Second\n")), vec!["Second"]);
        assert_eq!(
            lines_of(buffer.process_chunk(b"Third\nFourth\n")),
            vec!["Third", "Fourth"]
        );
    }

    #[test]
    fn test_partial_then_complete() {
        let mut buffer = StreamBuffer::new();

        assert!(lines_of(buffer.process_chunk(b"Partial")).is_empty());

        let lines = lines_of(buffer.process_chunk(b" line\nComplete\n"));
        assert_eq!(lines, vec!["Partial line", "Complete"]);
    }

    #[test]
    fn test_complete_lines_with_trailing_incomplete() {
        let mut buffer = StreamBuffer::new();

        let lines = lines_of(buffer.process_chunk(b"Line1\nLine2\nIncomplete"));
        assert_eq!(lines, vec!["Line1", "Line2"]);
        assert_eq!(buffer.len(), 10); // "Incomplete" = 10 bytes remains

        let lines = lines_of(buffer.process_chunk(b" data\n"));
        assert_eq!(lines, vec!["Incomplete data"]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_crlf_and_empty_lines() {
        let mut buffer = StreamBuffer::new();

        let lines = lines_of(buffer.process_chunk(b"a\r\n\n\r\nb\n"));
        assert_eq!(lines, vec!["a", "b"]);

        // `\r` split from its `\n` by a chunk boundary is still stripped.
        assert!(lines_of(buffer.process_chunk(b"c\r")).is_empty());
        assert_eq!(lines_of(buffer.process_chunk(b"\n")), vec!["c"]);
    }

    // ==========================================================================
    // Invalid UTF-8: only the faulty line is dropped
    // ==========================================================================

    #[test]
    fn test_invalid_line_between_valid_lines() {
        let mut buffer = StreamBuffer::new();

        let outcome = buffer.process_chunk(
            b"{\"_msg\":\"before\"}\n{\"_msg\":\"bad \xff\xfe\"}\n{\"_msg\":\"after\"}\n",
        );
        assert_eq!(
            outcome.lines,
            vec![r#"{"_msg":"before"}"#, r#"{"_msg":"after"}"#]
        );
        assert_eq!(outcome.invalid_utf8, 1);
        assert!(outcome.oversized.is_empty());
    }

    #[test]
    fn test_two_invalid_lines_in_one_chunk() {
        let mut buffer = StreamBuffer::new();

        let outcome = buffer.process_chunk(b"\x80\x81\nok\n\xE4\xB8\n");
        assert_eq!(outcome.lines, vec!["ok"]);
        assert_eq!(outcome.invalid_utf8, 2);
    }

    #[test]
    fn test_pending_fragment_kept_after_invalid_line() {
        let mut buffer = StreamBuffer::new();

        // Invalid complete line, then "Caf" + first byte of é.
        let outcome = buffer.process_chunk(b"bad \xff\nCaf\xC3");
        assert!(outcome.lines.is_empty());
        assert_eq!(outcome.invalid_utf8, 1);
        assert_eq!(buffer.len(), 4);

        let lines = lines_of(buffer.process_chunk(&[0xA9, 0x0A]));
        assert_eq!(lines, vec!["Café"]);
    }

    #[test]
    fn test_invalid_line_spanning_chunks() {
        let mut buffer = StreamBuffer::new();

        assert!(lines_of(buffer.process_chunk(b"start \xff")).is_empty());
        let outcome = buffer.process_chunk(b" end\nnext\n");
        assert_eq!(outcome.lines, vec!["next"]);
        assert_eq!(outcome.invalid_utf8, 1);
    }

    // ==========================================================================
    // MAX_LINE_SIZE limit
    // ==========================================================================

    #[test]
    fn test_line_at_exact_limit_is_kept() {
        let mut buffer = StreamBuffer::new();
        let mut chunk = vec![b'x'; MAX_LINE_SIZE];
        chunk.push(b'\n');

        let lines = lines_of(buffer.process_chunk(&chunk));
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].len(), MAX_LINE_SIZE);
    }

    #[test]
    fn test_pending_fragment_at_exact_limit_is_kept() {
        let mut buffer = StreamBuffer::new();

        assert!(lines_of(buffer.process_chunk(&vec![b'x'; MAX_LINE_SIZE])).is_empty());
        assert_eq!(buffer.len(), MAX_LINE_SIZE);

        let lines = lines_of(buffer.process_chunk(b"\n"));
        assert_eq!(lines[0].len(), MAX_LINE_SIZE);
    }

    #[test]
    fn test_complete_line_over_limit_is_dropped() {
        let mut buffer = StreamBuffer::new();
        let mut chunk = vec![b'x'; MAX_LINE_SIZE + 1];
        chunk.extend_from_slice(b"\nnext\n");

        let outcome = buffer.process_chunk(&chunk);
        assert_eq!(outcome.lines, vec!["next"]);
        assert_eq!(outcome.oversized, vec![MAX_LINE_SIZE + 1]);
        assert!(!buffer.discarding);
    }

    #[test]
    fn test_buffered_line_completed_over_limit_is_dropped() {
        let mut buffer = StreamBuffer::new();
        let half = vec![b'x'; MAX_LINE_SIZE / 2 + 1];

        assert!(lines_of(buffer.process_chunk(&half)).is_empty());

        let mut chunk = half.clone();
        chunk.extend_from_slice(b"\nnext\n");
        let outcome = buffer.process_chunk(&chunk);
        assert_eq!(outcome.lines, vec!["next"]);
        assert_eq!(outcome.oversized, vec![2 * half.len()]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_pending_fragment_over_limit_starts_discarding() {
        let mut buffer = StreamBuffer::new();

        let outcome = buffer.process_chunk(&vec![b'x'; MAX_LINE_SIZE + 1]);
        assert!(outcome.lines.is_empty());
        assert_eq!(outcome.oversized, vec![MAX_LINE_SIZE + 1]);
        assert!(buffer.is_empty());
        assert!(buffer.discarding);
    }

    #[test]
    fn test_oversized_tail_skipped_over_several_chunks() {
        let mut buffer = StreamBuffer::new();
        let half = vec![b'x'; MAX_LINE_SIZE / 2 + 1];

        assert!(lines_of(buffer.process_chunk(&half)).is_empty());
        // Accumulation crosses the limit: one record, buffer dropped.
        let outcome = buffer.process_chunk(&half);
        assert_eq!(outcome.oversized, vec![2 * half.len()]);
        assert!(buffer.is_empty());

        // The rest of the line, without `\n`, is ignored and not recorded again.
        assert_eq!(buffer.process_chunk(&half), ChunkOutcome::default());
        assert_eq!(buffer.process_chunk(b"more\xff"), ChunkOutcome::default());
        assert!(buffer.is_empty());

        // The end of the oversized line is never emitted; the next line is.
        let outcome = buffer.process_chunk(b"end of the line\"}\n{\"_msg\":\"next\"}\n");
        assert_eq!(
            outcome,
            ChunkOutcome {
                lines: vec![r#"{"_msg":"next"}"#.to_string()],
                ..ChunkOutcome::default()
            }
        );
        assert!(!buffer.discarding);
    }

    #[test]
    fn test_oversized_tail_ending_in_same_chunk_as_next_fragment() {
        let mut buffer = StreamBuffer::new();

        buffer.process_chunk(&vec![b'x'; MAX_LINE_SIZE + 1]);
        let outcome = buffer.process_chunk(b"tail\npartial");
        assert_eq!(outcome, ChunkOutcome::default());
        assert_eq!(buffer.len(), 7);
        assert_eq!(lines_of(buffer.process_chunk(b"\n")), vec!["partial"]);
    }

    #[test]
    fn test_valid_lines_before_overflow_in_same_chunk_are_emitted() {
        let mut buffer = StreamBuffer::new();
        let mut chunk = b"{\"_msg\":\"a\"}\n".to_vec();
        chunk.extend(vec![b'x'; MAX_LINE_SIZE + 1]);

        let outcome = buffer.process_chunk(&chunk);
        assert_eq!(outcome.lines, vec![r#"{"_msg":"a"}"#]);
        assert_eq!(outcome.oversized, vec![MAX_LINE_SIZE + 1]);
        assert!(buffer.discarding);
    }

    #[test]
    fn test_clear_resets_discarding() {
        let mut buffer = StreamBuffer::new();

        buffer.process_chunk(&vec![b'x'; MAX_LINE_SIZE + 1]);
        assert!(buffer.discarding);

        buffer.clear();
        assert!(!buffer.discarding);
        assert!(buffer.is_empty());

        // First bytes of the new connection are processed normally.
        assert_eq!(lines_of(buffer.process_chunk(b"fresh\n")), vec!["fresh"]);
    }

    #[test]
    fn test_clear_drops_pending_fragment() {
        let mut buffer = StreamBuffer::new();

        buffer.process_chunk(b"old partial");
        buffer.clear();
        assert_eq!(lines_of(buffer.process_chunk(b"new\n")), vec!["new"]);
    }
}
