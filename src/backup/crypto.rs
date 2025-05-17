//! Cryptographic routines for key derivation (`PBKDF2`), `AES` key wrap/unwrap, and `CBC` encryption/decryption.

use crate::backup::types::{Manifest, ProtectionClassKey};
use crate::error::{BackupError, Result};
use std::collections::HashMap;

use aes::cipher::{
    BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7, generic_array::GenericArray,
};
use aes::{Aes128, Aes192, Aes256}; // Import all AES variants
use aes_kw::Kek;
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1; // For PBKDF2
use sha2::Sha256; // For PBKDF2

// Define CBC mode for AES-256
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;

/// Derive the 32-byte encryption key from a user password using `PBKDF2`.
///
/// # Arguments
/// * `password` - User-supplied password bytes.
/// * `dpsl` - `DPSL` parameter from the key bag for first `PBKDF2` pass.
/// * `dpic` - `DPIC` iteration count parameter for the first `PBKDF2` pass.
/// * `salt` - Salt from the backup key bag for second `PBKDF2` pass.
/// * `iter` - Iteration count for the second `PBKDF2` pass (`HMAC-SHA1`).
///
/// # Returns
/// A 32-byte key for use in AES-based decryption.
///
/// # Errors
/// Never fails unless PBKDF2 implementation panics.
pub fn derive_key_from_password(
    password: &[u8],
    dpsl: &[u8],
    dpic: u32,
    salt: &[u8],
    iter: u32,
) -> Result<Vec<u8>> {
    let mut derived_pw = vec![0u8; 32]; // iOS backup key is 32 bytes (AES-256)
    let mut key = vec![0u8; 32]; // iOS backup key is 32 bytes (AES-256)
    eprintln!("Deriving key from password...");
    // TODO: Use a faster lib here
    pbkdf2_hmac::<Sha256>(password, dpsl, dpic, &mut derived_pw);
    pbkdf2_hmac::<Sha1>(&derived_pw, salt, iter, &mut key);
    Ok(key)
}

/// Unwrap (decrypt) all protection class keys from the Manifest's key bag.
///
/// # Arguments
/// * `main_key` - The derived 32-byte master key (Kmaster).
/// * `plist_info` - Parsed `Manifest.plist` containing `backup_key_bag`.
///
/// # Returns
/// A map of class ID to its unwrapped AES key.
///
/// # Errors
/// Returns `BackupError::Crypto` or `KeyUnwrapFailed` if unwrapping fails.
pub fn unlock_keys_from_manifest(
    main_key: &[u8], // This is Kmaster, should be 32 bytes for AES-256
    plist_info: &Manifest,
) -> Result<HashMap<u32, ProtectionClassKey>> {
    if main_key.len() != 32 {
        return Err(BackupError::Crypto(format!(
            "Main key for unlocking class keys must be 32 bytes for AES-256, got {}",
            main_key.len()
        )));
    }
    let mut unlocked_keys = HashMap::new();
    let key_bag = plist_info
        .backup_key_bag
        .as_ref()
        .ok_or_else(|| BackupError::Crypto("BackupKeyBag not found in PlistInfo".to_string()))?;

    for (class_id, class_key_data) in &key_bag.class_keys {
        // Skip classes without WPKY
        let wpky = match &class_key_data.wpky {
            Some(w) => w,
            None => continue,
        };

        // Check wrap flags for passcode protection (bit 0x02)
        let wrap_bytes = match &class_key_data.wrap {
            Some(w) => w,
            None => continue,
        };

        // Parse wrap flag as big-endian u32
        let wrap_val = u32::from_be_bytes(wrap_bytes.as_slice().try_into().unwrap());
        if wrap_val & 0x02 == 0 {
            continue; // Skip keys not protected by passcode
        }

        // Unwrap class key using AES key wrap (RFC 3394)
        let unwrapped = aes_kw_unwrap_bytes(main_key, wpky)
            .map_err(|_| BackupError::KeyUnwrapFailed(*class_id))?;

        unlocked_keys.insert(
            *class_id,
            ProtectionClassKey {
                class_id: *class_id,
                key: unwrapped,
            },
        );
    }
    Ok(unlocked_keys)
}

/// Unwrap (decrypt) a single file key for a given protection class.
///
/// # Arguments
/// * `class_id` - Numeric protection class identifier.
/// * `wrapped_file_key` - Encrypted file key blob.
/// * `unlocked_class_keys` - Map from class ID to unwrapped class keys.
///
/// # Returns
/// The raw file key bytes.
///
/// # Errors
/// `BackupError::Crypto` if unwrapping fails.
pub fn unwrap_key_for_class(
    class_id: u32,
    wrapped_file_key: &[u8],
    unlocked_class_keys: &HashMap<u32, ProtectionClassKey>,
) -> Result<Vec<u8>> {
    let class_key_entry = unlocked_class_keys.get(&class_id).ok_or_else(|| {
        BackupError::Crypto(format!(
            "Protection class {} key not found in unlocked keys",
            class_id
        ))
    })?;
    let class_key_bytes = class_key_entry.key.as_slice();
    // Use helper to unwrap file key
    aes_kw_unwrap_bytes(class_key_bytes, wrapped_file_key).map_err(|_| {
        BackupError::Crypto(format!("Failed to unwrap file key for class {}", class_id))
    })
}

/// Decrypt data using AES-256 CBC with PKCS7 padding and a zero IV.
///
/// # Arguments
/// * `data` - Encrypted ciphertext bytes.
/// * `key` - 32-byte AES key.
///
/// # Returns
/// The decrypted plaintext bytes.
///
/// # Errors
/// Returns `BackupError::Crypto` or `InvalidCryptoDataLength` on failure.
pub fn aes_decrypt_cbc_with_padding(
    data: &[u8], // ciphertext
    key: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != 32 {
        // Assuming AES-256 for this function
        return Err(BackupError::InvalidCryptoDataLength {
            expected: 32,
            actual: key.len(),
        });
    }

    // Ensure data length is a multiple of 16 bytes (AES block size)
    let data_len = if data.len() % 16 != 0 {
        data.len() - (data.len() % 16)
    } else {
        data.len()
    };

    let iv_bytes = [0u8; 16];
    let iv = GenericArray::from_slice(&iv_bytes);

    // Create buffer with truncated data if necessary
    let mut buf = if data.len() == data_len {
        data.to_vec()
    } else {
        data[..data_len].to_vec()
    };

    let key_ga = GenericArray::from_slice(key);
    let cipher = Aes256CbcDec::new(key_ga, iv);

    let pt_len = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| BackupError::Crypto(format!("AES CBC decryption error (padding): {:?}", e)))?
        .len();

    buf.truncate(pt_len);
    Ok(buf)
}

/// Encrypt data using AES-256 CBC with PKCS7 padding and a zero IV.
///
/// # Arguments
/// * `data` - Plaintext bytes.
/// * `key` - 32-byte AES key.
///
/// # Returns
/// The ciphertext bytes.
///
/// # Errors
/// Returns `BackupError::Crypto` or `InvalidCryptoDataLength` on failure.
#[allow(dead_code)]
pub fn aes_encrypt_cbc_with_padding(
    data: &[u8], // plaintext
    key: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != 32 {
        // Assuming AES-256 for this function
        return Err(BackupError::InvalidCryptoDataLength {
            expected: 32,
            actual: key.len(),
        });
    }
    let iv_bytes = [0u8; 16];
    let iv = GenericArray::from_slice(&iv_bytes);

    let mut buffer = vec![0u8; data.len() + 16]; // Max possible size for ciphertext with padding
    buffer[..data.len()].copy_from_slice(data);

    let key_ga = GenericArray::from_slice(key);
    let cipher = Aes256CbcEnc::new(key_ga, iv);

    let ct_len = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, data.len())
        .map_err(|e| BackupError::Crypto(format!("AES CBC encryption error (padding): {:?}", e)))?
        .len();

    buffer.truncate(ct_len);
    Ok(buffer)
}

/// Internal helper to unwrap AES Key Wrap (RFC 3394) based on key length.
///
/// # Arguments
/// * `kek_bytes` - Key Encryption Key (must be 16, 24, or 32 bytes).
/// * `wrapped_data` - Wrapped key data (must be at least 8 bytes).
///
/// # Returns
/// The unwrapped key data.
///
/// # Errors
/// Returns `BackupError::Crypto` if the unwrapping fails.
pub(crate) fn aes_kw_unwrap_bytes(kek_bytes: &[u8], wrapped_data: &[u8]) -> Result<Vec<u8>> {
    if wrapped_data.len() <= 8 {
        return Err(BackupError::Crypto(format!(
            "Wrapped data is too short ({} bytes)",
            wrapped_data.len()
        )));
    }

    let mut unwrapped = vec![0u8; wrapped_data.len() - 8]; // Result is wrapped_len - 8 bytes
    match kek_bytes.len() {
        16 => {
            // AES-128 key unwrap
            let kek = Kek::<Aes128>::new(GenericArray::from_slice(kek_bytes));
            kek.unwrap(wrapped_data, &mut unwrapped)
                // .map_err(|_| BackupError::Crypto("AES 128 Key Unwrap failed".to_string()))?;
                .unwrap();
        }
        24 => {
            // AES-192 key unwrap
            let kek = Kek::<Aes192>::new(GenericArray::from_slice(kek_bytes));
            kek.unwrap(wrapped_data, &mut unwrapped)
                // .map_err(|_| BackupError::Crypto("AES 192 Key Unwrap failed".to_string()))?;
                .unwrap();
        }
        32 => {
            // AES-256 key unwrap
            let kek = Kek::<Aes256>::new(GenericArray::from_slice(kek_bytes));
            kek.unwrap(wrapped_data, &mut unwrapped)
                // .map_err(|_| BackupError::Crypto("AES 256 Key Unwrap failed".to_string()))?;
                .unwrap();
        }
        _ => {
            return Err(BackupError::Crypto(format!(
                "Invalid KEK length: {} bytes (must be 16, 24, or 32)",
                kek_bytes.len()
            )));
        }
    }
    Ok(unwrapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::generic_array::GenericArray;
    use aes::{Aes128, Aes192, Aes256};
    use aes_kw::Kek;

    #[test]
    fn test_derive_key_consistency() {
        let salt = b"saltsalt";
        let key1 = derive_key_from_password(b"password", &[], 0, salt, 1000).unwrap();
        let key2 = derive_key_from_password(b"password", &[], 0, salt, 1000).unwrap();
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_aes_cbc_roundtrip() {
        let key = vec![0x42; 32];
        let data = b"The quick brown fox jumps over the lazy dog";
        let ciphertext = aes_encrypt_cbc_with_padding(data, &key).unwrap();
        assert_ne!(ciphertext, data);
        let plaintext = aes_decrypt_cbc_with_padding(&ciphertext, &key).unwrap();
        assert_eq!(plaintext, data);
    }

    fn wrap_and_unwrap(kek_bytes: &[u8], plain: &[u8]) {
        let mut wrapped = vec![0u8; plain.len() + 8];
        match kek_bytes.len() {
            16 => {
                let kek = Kek::<Aes128>::new(GenericArray::from_slice(kek_bytes));
                kek.wrap(plain, &mut wrapped).unwrap();
            }
            24 => {
                let kek = Kek::<Aes192>::new(GenericArray::from_slice(kek_bytes));
                kek.wrap(plain, &mut wrapped).unwrap();
            }
            32 => {
                let kek = Kek::<Aes256>::new(GenericArray::from_slice(kek_bytes));
                kek.wrap(plain, &mut wrapped).unwrap();
            }
            _ => panic!("Invalid KEK length"),
        }
        let unwrapped = aes_kw_unwrap_bytes(kek_bytes, &wrapped).unwrap();
        assert_eq!(unwrapped, plain);
    }

    #[test]
    fn test_key_wrap_unwrap_128() {
        let kek = [0x0b; 16];
        let data = b"12345678ABCDEFGH";
        wrap_and_unwrap(&kek, data);
    }

    #[test]
    fn test_key_wrap_unwrap_192() {
        let kek = [0x0c; 24];
        let data = b"12345678ABCDEFGH";
        wrap_and_unwrap(&kek, data);
    }

    #[test]
    fn test_key_wrap_unwrap_256() {
        let kek = [0x0d; 32];
        let data = b"12345678ABCDEFGH";
        wrap_and_unwrap(&kek, data);
    }

    #[test]
    fn test_unwrap_key_for_class() {
        use std::collections::HashMap;
        let class_id = 100;
        // Simulate a class key (16-byte for AES-128)
        let class_key = vec![0x1f; 16];
        let pck = ProtectionClassKey {
            class_id,
            key: class_key.clone(),
        };
        let mut keys = HashMap::new();
        keys.insert(class_id, pck);

        // Create a dummy file key and wrap it
        let file_key = b"example_file_key";
        let mut wrapped = vec![0u8; file_key.len() + 8];
        let kek = GenericArray::from_slice(&class_key);
        Kek::<Aes128>::new(kek)
            .wrap(file_key, &mut wrapped)
            .unwrap();

        // Now unwrap via our API
        let unwrapped = unwrap_key_for_class(class_id, &wrapped, &keys).unwrap();
        assert_eq!(unwrapped, file_key);
    }

    #[test]
    fn test_aes_kw_unwrap_errors() {
        // Wrapped data too short
        let kek = vec![0u8; 16];
        let short_data = vec![0u8; 8];
        let err = aes_kw_unwrap_bytes(&kek, &short_data).unwrap_err();
        match err {
            BackupError::Crypto(msg) => assert!(msg.contains("too short")),
            _ => panic!("Expected Crypto error for short data"),
        }
        // Invalid KEK length
        let invalid_kek = vec![0u8; 10];
        let wrapped = vec![0u8; 16];
        let err2 = aes_kw_unwrap_bytes(&invalid_kek, &wrapped).unwrap_err();
        match err2 {
            BackupError::Crypto(msg) => assert!(msg.contains("Invalid KEK length")),
            _ => panic!("Expected Crypto error for invalid KEK length"),
        }
    }

    #[test]
    fn test_wrap_and_unwrap_roundtrip() {
        let plain = b"secret12";
        for &kek_len in &[16usize, 24, 32] {
            let kek_bytes = vec![0x55u8; kek_len];
            // Wrap
            let mut wrapped = vec![0u8; plain.len() + 8];
            match kek_len {
                16 => {
                    let kek = Kek::<Aes128>::new(GenericArray::from_slice(&kek_bytes));
                    kek.wrap(plain, &mut wrapped).expect("Wrap failed");
                }
                24 => {
                    let kek = Kek::<Aes192>::new(GenericArray::from_slice(&kek_bytes));
                    kek.wrap(plain, &mut wrapped).expect("Wrap failed");
                }
                32 => {
                    let kek = Kek::<Aes256>::new(GenericArray::from_slice(&kek_bytes));
                    kek.wrap(plain, &mut wrapped).expect("Wrap failed");
                }
                _ => unreachable!(),
            }
            let unwrapped = aes_kw_unwrap_bytes(&kek_bytes, &wrapped).expect("Unwrap failed");
            assert_eq!(unwrapped, plain);
        }
    }

    #[test]
    fn test_aes_encrypt_invalid_key_length() {
        let data = b"hello";
        // key too short
        let short_key = vec![0u8; 16];
        let err = aes_encrypt_cbc_with_padding(data, &short_key).unwrap_err();
        match err {
            BackupError::InvalidCryptoDataLength {
                actual,
                expected: _,
            } => assert_eq!(actual, 16),
            _ => panic!("Expected InvalidCryptoDataLength for short key"),
        }
        // key too long
        let long_key = vec![0u8; 64];
        let err2 = aes_encrypt_cbc_with_padding(data, &long_key).unwrap_err();
        match err2 {
            BackupError::InvalidCryptoDataLength {
                actual,
                expected: _,
            } => assert_eq!(actual, 64),
            _ => panic!("Expected InvalidCryptoDataLength for long key"),
        }
    }

    #[test]
    fn test_aes_decrypt_invalid_key_length() {
        let cipher = vec![0u8; 16];
        let short_key = vec![0u8; 24];
        let err = aes_decrypt_cbc_with_padding(&cipher, &short_key).unwrap_err();
        match err {
            BackupError::InvalidCryptoDataLength { actual, expected } => {
                assert_eq!(actual, 24);
                assert_eq!(expected, 32);
            }
            _ => panic!("Expected InvalidCryptoDataLength with actual=24, expected=32"),
        }
    }

    #[test]
    fn test_derive_key_length_and_determinism() {
        let password = b"password";
        let dpsl = b"salt1";
        let dpic = 2;
        let salt = b"salt2";
        let iter = 3;
        let key1 = derive_key_from_password(password, dpsl, dpic, salt, iter).unwrap();
        let key2 = derive_key_from_password(password, dpsl, dpic, salt, iter).unwrap();
        // Key must be 32 bytes and deterministic
        assert_eq!(key1.len(), 32);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_aes_encrypt_decrypt_empty_data() {
        // AES-256 key of zeros
        let key = vec![0u8; 32];
        // Encrypt empty plaintext
        let ciphertext = aes_encrypt_cbc_with_padding(&[], &key).unwrap();
        // Even empty plaintext should produce one full block of padding
        assert_eq!(ciphertext.len(), 16);
        // Decrypt back
        let plaintext = aes_decrypt_cbc_with_padding(&ciphertext, &key).unwrap();
        assert_eq!(plaintext.len(), 0);
    }

    #[test]
    fn test_aes_decrypt_trims_non_multiple_of_block_size() {
        // Prepare a valid ciphertext for "hello"
        let key = vec![0u8; 32];
        let original = b"hello";
        let mut ciphertext = aes_encrypt_cbc_with_padding(original, &key).unwrap();
        // Append extra bytes that should be ignored
        ciphertext.extend(&[0u8; 5]);
        // Decrypt will truncate to a multiple of block size
        let plaintext = aes_decrypt_cbc_with_padding(&ciphertext, &key).unwrap();
        assert_eq!(plaintext, original);
    }
}
