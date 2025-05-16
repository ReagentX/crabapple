//! Utility functions for hexadecimal encoding/decoding, path expansion, and default backup path resolution.

use crate::Result;
use crate::error::BackupError;

/// Decode a hexadecimal string into a byte vector.
///
/// # Arguments
///
/// * `hex_string` - String slice containing hex characters (even length).
///
/// # Errors
/// Returns `BackupError::HexDecode` if the string has odd length or invalid chars.
pub fn hex_decode(hex_string: &str) -> Result<Vec<u8>> {
    if hex_string.len() % 2 != 0 {
        return Err(BackupError::HexDecode(
            "Input string has odd length".to_string(),
        ));
    }

    (0..hex_string.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_string[i..i + 2], 16))
        .collect::<std::result::Result<Vec<u8>, _>>()
        .map_err(|e| BackupError::HexDecode(format!("Invalid hex character: {}", e)))
}

/// Encode a slice of bytes as a lowercase hexadecimal string.
///
/// # Arguments
///
/// * `bytes` - Byte slice to encode.
///
/// # Returns
/// A `String` of hex digits (two chars per input byte).
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Iterate over a TLV‐encoded blob: 4‐byte tag, 4‐byte big‐endian length, then `length` bytes of value.
pub fn tlv_blocks(blob: &[u8]) -> impl Iterator<Item = ([u8; 4], Vec<u8>)> + '_ {
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
    use crate::error::BackupError;

    #[test]
    fn test_hex_encode_roundtrip() {
        let data = b"rust";
        let encoded = hex_encode(data);
        assert_eq!(encoded, "72757374");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_decode_odd_length() {
        let err = hex_decode("abc").unwrap_err();
        match err {
            BackupError::HexDecode(msg) => assert!(msg.contains("odd length")),
            _ => panic!("Expected HexDecode error"),
        }
    }

    #[test]
    fn test_hex_decode_invalid_char() {
        let err = hex_decode("zz").unwrap_err();
        match err {
            BackupError::HexDecode(msg) => assert!(msg.contains("Invalid hex character")),
            _ => panic!("Expected HexDecode error"),
        }
    }

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
}
