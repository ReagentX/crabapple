//! Module for loading, decrypting, and querying the `Manifest.db` of an iOS backup.

use plist::Value;
use rusqlite::Connection;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::backup::crypto::{aes_decrypt_cbc_with_padding, aes_kw_unwrap_bytes}; // For decrypting DB if needed
use crate::backup::types::{BackupFileEntry, DecryptedManifestDb, MBFile, ProtectionClassKey};
use crate::backup::util;
use crate::error::{BackupError, Result};

/// Represents the backup's `Manifest.db`, decrypted if necessary, and holds decryption info.
pub struct ManifestDb {
    decrypted_db_info: DecryptedManifestDb,
}

impl ManifestDb {
    /// Open (and decrypt if necessary) the backup's `Manifest.db`, returning a [`ManifestDb`].
    ///
    /// # Arguments
    /// * `db_path` - Filesystem path to the `Manifest.db` file.
    /// * `is_encrypted` - Indicates if the backup is encrypted.
    /// * `manifest_key_data` - Optional raw key blob for `Manifest.db` decryption.
    /// * `class_keys` - Unwrapped class keys for key bag decryption.
    ///
    /// # Errors
    /// Returns [`BackupError::ManifestDbNotFound`] if the DB file is missing, or [`BackupError::Crypto`] on decryption errors.
    pub fn new(
        db_path: &Path,
        is_encrypted: bool,
        manifest_key_data: Option<&[u8]>,
        class_keys: &Option<HashMap<u32, ProtectionClassKey>>,
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

            // TODO: Abstract this as a function like `decrypt_file()` somewhere
            let (class_bytes, key_bytes) = manifest_key_bytes.split_at(4);
            let manifest_class = u32::from_le_bytes(class_bytes.try_into().unwrap());

            let class_key_entry = class_keys
                .as_ref()
                .and_then(|keys| keys.get(&manifest_class)) // Class 4
                .ok_or_else(|| {
                    BackupError::Crypto(format!(
                        "Class {manifest_class} key not found, needed to decrypt Manifest.db key"
                    ))
                })?;

            let key = aes_kw_unwrap_bytes(&class_key_entry.key, key_bytes)
                .map_err(|_| BackupError::KeyUnwrapFailed(manifest_class))?;

            let decrypted_manifest_db = aes_decrypt_cbc_with_padding(&buffer, &key)?;

            // TODO: Open the database in memory
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

    /// Consume this [`ManifestDb` ]and return the underlying [`DecryptedManifestDb`] information.
    pub fn into_decrypted_db_info(self) -> DecryptedManifestDb {
        self.decrypted_db_info
    }
}

/// Query all unique domains present in the `Manifest.db`.
///
/// # Arguments
/// * `conn` - An open [`rusqlite::Connection`] to the manifest database.
///
/// # Errors
/// Returns `BackupError::Database` on query failures.
pub fn query_all_domains(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT
             CASE
                 WHEN INSTR(domain, '-') > 0
                 THEN SUBSTR(domain, 1, INSTR(domain, '-') - 1)
                 ELSE
                 domain
             END AS domain
             FROM Files;",
    )?;
    let mut rows = stmt.query([])?;
    let mut domains = Vec::new();
    while let Some(row) = rows.next()? {
        domains.push(row.get(0)?);
    }
    Ok(domains)
}

/// Query all file entries from the `Manifest.db`.
///
/// # Arguments
/// * `conn` - An open rusqlite `Connection`.
///
/// # Errors
/// Returns [`BackupError::Database`] if the `SQL` query or blob reading fails.
pub fn query_all_files(conn: &Connection) -> Result<Vec<BackupFileEntry>> {
    let mut stmt =
        conn.prepare("SELECT rowid, fileID, domain, relativePath, flags, file FROM Files")?;
    let mut rows = stmt.query([])?;
    let mut entries = Vec::new();
    while let Some(row) = rows.next()? {
        let file_id = row.get(0)?;

        let blob = conn
            .blob_open(rusqlite::DatabaseName::Main, "Files", "file", file_id, true)
            .ok()
            .unwrap();

        let plist = Value::from_reader(blob)
            .map_err(|_| BackupError::InvalidTlvData("Failed to parse file plist".to_string()))?;

        let mbfile = MBFile::from_plist(plist).map_err(|_| {
            BackupError::InvalidTlvData("Failed to parse MBFile from plist".to_string())
        })?;

        entries.push(BackupFileEntry {
            file_id: row.get(1)?,
            domain: row.get(2)?,
            relative_path: row.get(3)?,
            flags: row.get(4)?,
            metadata: mbfile, // Store the plist as metadata
        });
    }
    Ok(entries)
}

/// Query a single file entry by its file ID in the `Manifest.db`.
///
/// # Arguments
/// * `conn` - An open rusqlite `Connection`.
/// * `path` - The `fileID` to look up in the `Files` table.
///
/// # Returns
/// `Ok(Some(entry))` if found, `Ok(None)` if not found.
///
/// # Errors
/// Returns [`BackupError::Database`] on query failures.
pub fn query_file_by_id(conn: &Connection, path: &str) -> Result<Option<BackupFileEntry>> {
    // Path in DB is typically Domain-RelativePath
    let mut stmt = conn.prepare(
        "SELECT rowid, fileID, domain, relativePath, flags, file FROM Files WHERE fileID = ?",
    )?;
    let mut rows = stmt.query([path])?;
    if let Some(row) = rows.next()? {
        let file_id = row.get(0)?;

        let blob = conn
            .blob_open(rusqlite::DatabaseName::Main, "Files", "file", file_id, true)
            .ok()
            .unwrap();

        let plist = Value::from_reader(blob)
            .map_err(|_| BackupError::InvalidTlvData("Failed to parse file plist".to_string()))?;

        let mbfile = MBFile::from_plist(plist).map_err(|_| {
            BackupError::InvalidTlvData("Failed to parse MBFile from plist".to_string())
        })?;

        Ok(Some(BackupFileEntry {
            file_id: row.get(1)?,
            domain: row.get(2)?,
            relative_path: row.get(3)?,
            flags: row.get(4)?,
            metadata: mbfile, // Store the plist as metadata
        }))
    } else {
        Ok(None)
    }
}
