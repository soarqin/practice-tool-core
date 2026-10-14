//! Boyer–Moore byte searches with whole-byte wildcards.
//!
//! `Some(byte)` matches that byte and `None` matches any byte. Both the
//! bad-character and good-suffix rules account for wildcards.

/// A preprocessed byte pattern that can be reused across multiple searches.
///
/// Preprocessing takes O(m²) time and O(m + 256) space for a pattern of length
/// m. Searches compare from right to left and use the larger of the
/// bad-character and good-suffix shifts, including for patterns containing
/// wildcards.
///
/// # Examples
///
/// ```
/// use practice_tool_core::boyer_moore::BoyerMoore;
///
/// let pattern = [Some(0x48), Some(0x8b), None, Some(0x90)];
/// let searcher = BoyerMoore::new(&pattern);
/// assert_eq!(searcher.find(&[0, 0x48, 0x8b, 0xff, 0x90]), Some(1));
/// assert_eq!(searcher.find(&[0x48, 0x8b, 0, 0x90]), Some(0));
/// ```
#[derive(Clone, Debug)]
pub struct BoyerMoore<'a> {
    pattern: &'a [Option<u8>],
    trailing_wildcards: usize,
    default_shift: usize,
    bad_character: [usize; 256],
    good_suffix: Vec<usize>,
}

impl<'a> BoyerMoore<'a> {
    /// Preprocess a pattern. `None` represents an unknown byte.
    pub fn new(pattern: &'a [Option<u8>]) -> Self {
        // Trailing wildcards only require enough remaining bytes. Excluding
        // them from the tables lets the known prefix retain its larger shifts.
        let len = pattern.iter().rposition(Option::is_some).map_or(0, |index| index + 1);
        let trailing_wildcards = pattern.len() - len;
        let pattern = &pattern[..len];

        // The last wildcard supersedes all earlier occurrences. Build shift
        // distances directly from the concrete suffix after it. Zero marks
        // the final byte; other distances handle final-byte mismatches.
        let suffix_start = pattern.iter().rposition(Option::is_none).map_or(0, |index| index + 1);
        let default_shift = len - suffix_start;
        let mut bad_character = [default_shift; 256];
        for (index, byte) in pattern.iter().enumerate().skip(suffix_start) {
            if let Some(byte) = byte {
                bad_character[*byte as usize] = len - index - 1;
            }
        }
        let mut good_suffix = vec![len; len];
        for shift in 1..len {
            // Two overlapping symbols conflict only if both are known and
            // different. A wildcard can match either symbol, but compatibility
            // is not transitive, so ordinary suffix/border preprocessing cannot
            // simply substitute wildcard comparisons for equality.
            let last_conflict = (shift..len)
                .rfind(|&index| match (pattern[index], pattern[index - shift]) {
                    (Some(left), Some(right)) => left != right,
                    _ => false,
                })
                .unwrap_or(0);

            // At a mismatch at index j, only j+1..len has matched. This shift
            // can preserve that suffix if all overlapping conflicts are <= j.
            for (index, suffix_shift) in good_suffix.iter_mut().enumerate().skip(last_conflict) {
                if *suffix_shift != len {
                    continue;
                }
                // The byte at the mismatch is known to differ from pattern[j].
                // Do not align it with the same known byte again (the strong
                // good-suffix rule). A wildcard remains a possible alignment.
                if index >= shift
                    && pattern[index].is_some()
                    && pattern[index - shift] == pattern[index]
                {
                    continue;
                }
                *suffix_shift = shift;
            }
        }

        Self { pattern, trailing_wildcards, default_shift, bad_character, good_suffix }
    }

    /// Return the offset of the first match, or `None` if there is no match.
    ///
    /// An empty pattern matches at offset zero, including in an empty slice.
    pub fn find(&self, bytes: &[u8]) -> Option<usize> {
        let bytes = &bytes[..bytes.len().checked_sub(self.trailing_wildcards)?];
        let len = self.pattern.len();
        if len == 0 {
            return Some(0);
        }
        let mut end = len - 1;

        loop {
            // Keep the common shift loop's increment invariant, so each next
            // address can be computed before the preceding lookup completes.
            while end < bytes.len() && self.bad_character[bytes[end] as usize] == self.default_shift
            {
                end += self.default_shift;
            }
            let tail_shift = self.bad_character[*bytes.get(end)? as usize];
            if tail_shift > 0 {
                // With an empty matched suffix, the bad-character shift is
                // already at least the good-suffix shift. This common mismatch
                // needs only a table lookup, even with wildcard patterns.
                end += tail_shift;
                continue;
            }

            let start = end + 1 - len;
            let mut unmatched = len - 1;
            while unmatched > 0 {
                let index = unmatched - 1;
                if self.pattern[index].is_some_and(|byte| byte != bytes[start + index]) {
                    break;
                }
                unmatched -= 1;
            }
            if unmatched == 0 {
                return Some(start);
            }

            let index = unmatched - 1;
            let byte = bytes[start + index];
            let bad_character = self.bad_character[byte as usize].saturating_sub(len - unmatched);
            let shift = bad_character.max(self.good_suffix[index]);
            end += shift;
        }
    }
}

/// Search once without retaining the preprocessed pattern.
///
/// Use [`BoyerMoore`] to share preprocessing across multiple byte slices.
pub fn search(bytes: &[u8], pattern: &[Option<u8>]) -> Option<usize> {
    BoyerMoore::new(pattern).find(bytes)
}

#[cfg(test)]
mod tests {
    use super::{search, BoyerMoore};

    fn reference_search(bytes: &[u8], pattern: &[Option<u8>]) -> Option<usize> {
        if pattern.is_empty() {
            return Some(0);
        }
        bytes.windows(pattern.len()).position(|window| {
            window.iter().zip(pattern).all(|(byte, expected)| expected.is_none_or(|x| *byte == x))
        })
    }

    fn sequences<T: Copy>(alphabet: &[T], max_len: usize) -> Vec<Vec<T>> {
        let mut sequences = Vec::new();
        for len in 0..=max_len {
            for mut value in 0..alphabet.len().pow(len as u32) {
                let mut sequence = Vec::with_capacity(len);
                for _ in 0..len {
                    sequence.push(alphabet[value % alphabet.len()]);
                    value /= alphabet.len();
                }
                sequences.push(sequence);
            }
        }
        sequences
    }

    #[test]
    fn handles_empty_and_short_inputs() {
        assert_eq!(search(&[], &[]), Some(0));
        assert_eq!(search(&[1, 2], &[]), Some(0));
        assert_eq!(search(&[], &[None]), None);
        assert_eq!(search(&[1], &[Some(1), None]), None);
        assert_eq!(search(&[0, 1], &[Some(1), None]), None);
        assert_eq!(search(&[1, 2], &[None, None]), Some(0));
        assert_eq!(search(&[1, 2], &[None, None, None]), None);
    }

    #[test]
    fn finds_first_match_at_slice_boundaries() {
        let searcher = BoyerMoore::new(&[Some(1), Some(2), Some(1)]);
        assert_eq!(searcher.find(&[1, 2, 1]), Some(0));
        assert_eq!(searcher.find(&[0, 0, 1, 2, 1]), Some(2));
        assert_eq!(searcher.find(&[1, 2, 1, 2, 1]), Some(0));
        assert_eq!(searcher.find(&[1, 2, 0, 2, 1]), None);
    }

    #[test]
    fn handles_leading_middle_and_trailing_wildcards() {
        assert_eq!(search(&[0, 0, 1, 2], &[None, Some(1), Some(2)]), Some(1));
        assert_eq!(search(&[0, 0, 0, 1], &[Some(0), None, Some(1)]), Some(1));
        assert_eq!(search(&[0, 1, 2, 3], &[Some(1), Some(2), None]), Some(1));
        assert_eq!(search(&[1, 0, 1, 2], &[Some(1), None, None]), Some(0));
        assert_eq!(search(&[0, 0, 1, 0, 1, 1], &[Some(1), None, Some(1), Some(1)]), Some(2));
    }

    #[test]
    fn handles_every_byte_value() {
        let bytes: Vec<_> = (u8::MIN..=u8::MAX).collect();
        for byte in u8::MIN..=u8::MAX {
            assert_eq!(search(&bytes, &[Some(byte)]), Some(byte as usize));
        }
        assert_eq!(search(&bytes, &[Some(0xfd), None, Some(0xff)]), Some(253));
        assert_eq!(search(&bytes, &[None, Some(0xff)]), Some(254));
    }

    #[test]
    fn agrees_with_reference_for_longer_patterns() {
        let mut state = 0x1234_5678_u32;
        let mut next_byte = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        };

        for case in 0..1024 {
            let len = case % 64 + 1;
            let mut bytes: Vec<_> = (0..256).map(|_| next_byte()).collect();
            let pattern: Vec<_> = (0..len)
                .map(|_| if next_byte() % 4 == 0 { None } else { Some(next_byte()) })
                .collect();
            if case % 2 == 0 {
                let start = next_byte() as usize % (bytes.len() - len + 1);
                for (byte, expected) in bytes[start..].iter_mut().zip(&pattern) {
                    if let Some(expected) = expected {
                        *byte = *expected;
                    }
                }
            }
            assert_eq!(search(&bytes, &pattern), reference_search(&bytes, &pattern));
        }
    }

    #[test]
    fn agrees_with_reference_for_exhaustive_short_patterns() {
        let texts = sequences(&[0, 1, 2], 6);
        for pattern in sequences(&[Some(0), Some(1), Some(2), None], 5) {
            let searcher = BoyerMoore::new(&pattern);
            for bytes in &texts {
                assert_eq!(
                    searcher.find(bytes),
                    reference_search(bytes, &pattern),
                    "bytes: {bytes:?}, pattern: {pattern:?}"
                );
            }
        }
    }
}
