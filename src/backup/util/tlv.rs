//! Tag-Length-Value encoding utilities.

/// Iterate through a `TLV‐encoded` blob, yielding tag-value pairs.
///
/// Each block consists of a `4`-byte tag, a `4`-byte big-endian length, followed by value bytes of that length.
///
/// # Arguments
/// * `blob` - Byte slice containing TLV-encoded data.
///
/// # Returns
/// An iterator yielding `(tag, value)` tuples, where `tag` is a `4`-byte identifier and `value` is the associated data.
pub(crate) fn tlv_blocks(blob: &[u8]) -> impl Iterator<Item = ([u8; 4], Vec<u8>)> + '_ {
    struct Iter<'a> {
        data: &'a [u8],
        pos: usize,
    }
    impl Iterator for Iter<'_> {
        type Item = ([u8; 4], Vec<u8>);
        fn next(&mut self) -> Option<Self::Item> {
            if self.pos + 8 > self.data.len() {
                return None;
            }
            let tag = self.data[self.pos..self.pos + 4].try_into().unwrap();
            let len = u32::from_be_bytes(self.data[self.pos + 4..self.pos + 8].try_into().unwrap())
                as usize;
            let start = self.pos + 8;
            let end = start + len;
            if end > self.data.len() {
                return None;
            }
            let value = self.data[start..end].to_vec();
            self.pos = end;
            Some((tag, value))
        }
    }
    Iter { data: blob, pos: 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_blocks_roundtrip() {
        // Construct a TLV blob: tag "ABCD", length 3, value [1,2,3], then tag "EFGH", length 2, value [4,5]
        let mut blob = Vec::new();
        blob.extend(b"ABCD");
        blob.extend(&3u32.to_be_bytes());
        blob.extend(&[1, 2, 3]);
        blob.extend(b"EFGH");
        blob.extend(&2u32.to_be_bytes());
        blob.extend(&[4, 5]);

        let mut iter = tlv_blocks(&blob);
        let (tag1, val1) = iter.next().expect("First TLV block missing");
        assert_eq!(&tag1, b"ABCD");
        assert_eq!(val1, vec![1, 2, 3]);
        let (tag2, val2) = iter.next().expect("Second TLV block missing");
        assert_eq!(&tag2, b"EFGH");
        assert_eq!(val2, vec![4, 5]);
        assert!(iter.next().is_none(), "Unexpected extra TLV block");
    }

    #[test]
    fn test_tlv_blocks_incomplete_blob() {
        // Blob with incomplete value (declared length longer than available)
        let mut blob = Vec::new();
        blob.extend(b"TAG1");
        blob.extend(&5u32.to_be_bytes()); // length 5
        blob.extend(&[1, 2]); // only 2 bytes present
        let mut iter = tlv_blocks(&blob);
        // Should not yield any blocks due to incomplete data
        assert!(iter.next().is_none());
    }
}
