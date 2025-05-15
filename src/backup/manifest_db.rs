//! Module for loading, decrypting, and querying the Manifest.db of an iOS backup.

use rusqlite::Connection;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::backup::crypto::{aes_decrypt_cbc_with_padding, aes_kw_unwrap_bytes}; // For decrypting DB if needed
use crate::backup::types::{BackupFileEntry, DecryptedManifestDb, ProtectionClassKey};
use crate::backup::util;
use crate::error::{BackupError, Result};

/// Represents the decrypted or raw Manifest.db and associated SQLCipher key.
///
/// Use `ManifestDb::new` to initialize and decrypt if needed.
pub struct ManifestDb {
    decrypted_db_info: DecryptedManifestDb,
}

impl ManifestDb {
    /// Open (and decrypt if necessary) the backup's `Manifest.db`.
    ///
    /// # Arguments
    /// * `db_path` - Path to the `Manifest.db` file.
    /// * `is_encrypted` - Whether the backup is encrypted.
    /// * `manifest_key_data` - Raw manifest key bytes for encryption.
    /// * `class_keys` - Map of unwrapped class keys.
    /// * `_device_backup_path` - Folder context for temp files.
    ///
    /// # Errors
    /// Returns `BackupError::ManifestDbNotFound` if file missing,
    /// or `BackupError::Crypto`/`General` for decryption errors.
    pub fn new(
        db_path: &Path,
        is_encrypted: bool,
        manifest_key_data: Option<&[u8]>,
        class_keys: &Option<HashMap<u32, ProtectionClassKey>>,
        _device_backup_path: &Path, // Marked as unused
    ) -> Result<Self> {
        if !db_path.exists() {
            return Err(BackupError::ManifestDbNotFound);
        }

        let mut db_bytes = File::open(db_path)?;
        let mut buffer = Vec::new();
        db_bytes.read_to_end(&mut buffer)?;

        let decrypted_db_info = if is_encrypted {
            let manifest_key_bytes = manifest_key_data.ok_or_else(|| {
                BackupError::Crypto(
                    "ManifestKey data not found in PlistInfo for encrypted Manifest.db".to_string(),
                )
            })?;

            let (class_bytes, key_bytes) = manifest_key_bytes.split_at(4);
            let manifest_class = u32::from_le_bytes(class_bytes.try_into().unwrap());

            let class_key_entry = class_keys
                .as_ref()
                .and_then(|keys| keys.get(&manifest_class)) // Class 4
                .ok_or_else(|| {
                    BackupError::Crypto(
                        "Class {manifest_class} key not found, needed to decrypt Manifest.db key"
                            .to_string(),
                    )
                })?;

            println!("Manifest key bytes: {:#?}", manifest_key_bytes);
            println!("Class {:?} key: {:#?}", class_bytes, class_key_entry);
            println!("Key bytes: {:#?}", key_bytes);

            let key = aes_kw_unwrap_bytes(&class_key_entry.key, key_bytes)
                .map_err(|_| BackupError::KeyUnwrapFailed(manifest_class))?;

            let decrypted_manifest_db = aes_decrypt_cbc_with_padding(&buffer, &key)?;

            let mut file = File::create("/tmp/decrypted.db")?;
            file.write_all(&decrypted_manifest_db)?;

            DecryptedManifestDb {
                db_path: PathBuf::from("/tmp/decrypted.db"),
                is_temporary: false, // Original DB path
                connection_string: db_path.to_string_lossy().into_owned(), // Path for direct open
                decryption_key: Some(util::hex_encode(&key)), // Key for SQLCipher
            }
        } else {
            DecryptedManifestDb {
                db_path: db_path.to_path_buf(),
                is_temporary: false,
                connection_string: db_path.to_string_lossy().into_owned(),
                decryption_key: None,
            }
        };
        Ok(Self { decrypted_db_info })
    }

    /// Consume `ManifestDb` and return the `DecryptedManifestDb` info.
    pub fn into_decrypted_db_info(self) -> DecryptedManifestDb {
        self.decrypted_db_info
    }
}

/// Query all file entries from the open `Manifest.db` connection.
///
/// # Arguments
/// * `conn` - An open rusqlite `Connection`.
///
/// # Errors
/// Returns `BackupError::Database` if a query fails.
// TODO: Fix the schema, support `file` plist stored in col
pub fn query_all_files(conn: &Connection) -> Result<Vec<BackupFileEntry>> {
    let mut stmt = conn.prepare(
        "SELECT fileID, domain, relativePath, flags, protectionclass, encryptionKey FROM Files",
    )?;
    let mut rows = stmt.query([])?;
    let mut entries = Vec::new();
    while let Some(row) = rows.next()? {
        entries.push(BackupFileEntry {
            file_id: row.get(0)?,
            domain: row.get(1)?,
            relative_path: row.get(2)?,
            flags: row.get(3)?,
            protection_class: row.get(4)?,
            encryption_key_wrapped: row.get(5)?, // This is a Vec<u8> if stored as BLOB
        });
    }
    Ok(entries)
}

/// Query a single file entry by its relative path.
///
/// # Arguments
/// * `conn` - An open rusqlite `Connection`.
/// * `path` - The file's relative path within the backup.
///
/// # Returns
/// `Ok(Some(entry))` if found, `Ok(None)` if not.
///
/// # Errors
/// Returns `BackupError::Database` if the query fails.
pub fn query_file_by_path(conn: &Connection, path: &str) -> Result<Option<BackupFileEntry>> {
    // Path in DB is typically Domain-RelativePath
    let mut stmt = conn.prepare(
        "SELECT fileID, domain, relativePath, flags, protectionclass, encryptionKey FROM Files WHERE relativePath = ?"
    )?;
    let mut rows = stmt.query([path])?;
    if let Some(row) = rows.next()? {
        Ok(Some(BackupFileEntry {
            file_id: row.get(0)?,
            domain: row.get(1)?,
            relative_path: row.get(2)?,
            flags: row.get(3)?,
            protection_class: row.get(4)?,
            encryption_key_wrapped: row.get(5)?,
        }))
    } else {
        Ok(None)
    }
}
