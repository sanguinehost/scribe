use blake3::Hasher;

pub struct MerlinDeduplicator;

impl MerlinDeduplicator {
    /// Computes a deterministic, byte-exact hash of the provided content.
    /// This is used for deduplication of chronicle events and lorebook entries.
    pub fn compute_hash(content: &[u8]) -> String {
        let mut hasher = Hasher::new();
        hasher.update(content);
        hasher.finalize().to_hex().to_string()
    }

    /// Checks if the content is a duplicate based on a list of existing hashes.
    pub fn is_duplicate(content: &[u8], existing_hashes: &[String]) -> bool {
        let hash = Self::compute_hash(content);
        existing_hashes.contains(&hash)
    }

    /// Normalizes text content for more robust byte-exact matching (e.g., trimming whitespace).
    pub fn normalize_content(content: &str) -> String {
        content.trim().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merlin_hashing() {
        let content1 = b"Hello Scribe";
        let content2 = b"Hello Scribe";
        let content3 = b"Hello scribe";

        assert_eq!(MerlinDeduplicator::compute_hash(content1), MerlinDeduplicator::compute_hash(content2));
        assert_ne!(MerlinDeduplicator::compute_hash(content1), MerlinDeduplicator::compute_hash(content3));
    }

    #[test]
    fn test_merlin_normalization() {
        let content = "  Hello Scribe  \n";
        assert_eq!(MerlinDeduplicator::normalize_content(content), "Hello Scribe");
    }
}
