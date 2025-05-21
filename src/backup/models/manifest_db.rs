//! Module for loading, decrypting, and querying the `Manifest.db` of an iOS backup.

use std::{
    collections::HashSet,
    fs::{File, remove_file},
    io::copy,
    path::{Path, PathBuf},
};

use plist::Value;
use rusqlite::Connection;

use crate::{
    backup::{
        crypto::{AesCbcDecryptReader, aes_kw_unwrap},
        models::{
            file::{BackupFileEntry, FileKeyPair, MBFile},
            manifest::manifest_plist::Manifest,
        },
        util::hex::hex_encode,
    },
    error::{BackupError, Result},
};

/// Represents the backup's `Manifest.db`, decrypted if necessary, and holds decryption info.
#[derive(Debug)]
pub struct ManifestDb {
    /// Path to the `SQLite` database file.
    pub db_path: PathBuf,
    /// Whether `db_path` points to a temporary decrypted file.
    pub is_temporary: bool,
    /// Connection string (usually the file path).
    pub connection_string: String,
    /// Optional hex-encoded decryption key used to decrypt the database.
    pub decryption_key: Option<String>,
    /// Connection to the manifest database
    pub conn: Option<Connection>,
}

impl ManifestDb {
    /// Open (and decrypt if necessary) the backup's `Manifest.db`, returning a [`ManifestDb`].
    ///
    /// # Arguments
    /// * `db_path` - Filesystem path to the `Manifest.db` file.
    /// * `manifest_data` - Data derived from the backup's `Manifest.plist`.
    ///
    /// # Errors
    /// Returns [`BackupError::ManifestDbNotFound`] if the DB file is missing, or [`BackupError::Crypto`] on decryption errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crabapple::{Backup, Authentication};
    /// use crabapple::backup::models::manifest_db;
    ///
    /// let backup = Backup::open(
    ///     "/path/to/backup",
    ///     &Authentication::Password("pass".into())
    /// )?;
    ///
    /// let db_path = backup.manifest_db_path();
    /// # Ok::<(), crabapple::error::BackupError>(())
    /// ```
    pub fn new(db_path: &Path, manifest: &Manifest) -> Result<Self> {
        if !db_path.exists() {
            return Err(BackupError::ManifestDbNotFound);
        }

        let decrypted_db_info = if manifest.manifest_data.is_encrypted {
            let manifest_key_bytes =
                manifest
                    .manifest_data
                    .manifest_key
                    .as_ref()
                    .ok_or_else(|| {
                        BackupError::Crypto(
                            "ManifestKey data not found in PlistInfo for encrypted Manifest.db"
                                .to_string(),
                        )
                    })?;

            // The first 4 bytes of `manifest_key_bytes` are interpreted as a little-endian
            // `u32` protection class identifier. The remainder is treated as an AES-key-wrapped
            // file key (RFC 3394).
            //
            // 1. Parse out the protection class ID.
            // 2. Look up the corresponding unwrapped class key in `class_keys`.
            // 3. Unwrap the file-specific AES key using AES-Key-Wrap.
            // 4. Decrypt `ciphertext` with AES-256-CBC (zero IV), stripping PKCS#7 padding.
            let manifest_file_key = FileKeyPair::new(manifest_key_bytes)?;

            let class_key_entry = manifest.get_class_key(manifest_file_key.protection_class_id)?;

            let key = aes_kw_unwrap(&class_key_entry.key, &manifest_file_key.file_key)
                .map_err(|_| BackupError::KeyUnwrapFailed(manifest_file_key.protection_class_id))?;

            // Decrypt the Manifest.db using the unwrapped key
            let db_bytes = File::open(db_path)?;
            let mut decrypted_manifest_db_stream = AesCbcDecryptReader::from(&db_bytes, &key)?;

            // Write decrypted Manifest.db into a platform-specific temporary directory
            let tmp_path = std::env::temp_dir().join("crabapple-Manifest.db");
            let mut file = File::create(&tmp_path)?;

            // Stream-decrypt directly into the temp file
            copy(&mut decrypted_manifest_db_stream, &mut file).map_err(|e| {
                BackupError::Crypto(format!("Failed writing decrypted Manifest.db: {e}"))
            })?;

            Self {
                db_path: tmp_path.clone(),
                is_temporary: true,
                connection_string: db_path.to_string_lossy().into_owned(), // Path for direct open
                decryption_key: Some(hex_encode(&key)),
                conn: Some(Connection::open(tmp_path).map_err(BackupError::Database)?),
            }
        } else {
            Self {
                db_path: db_path.to_path_buf(),
                is_temporary: false,
                connection_string: db_path.to_string_lossy().into_owned(),
                decryption_key: None,
                conn: Some(Connection::open(db_path).map_err(BackupError::Database)?),
            }
        };

        Ok(decrypted_db_info)
    }

    /// Returns the current manifest database connection, if available.
    ///
    /// # Returns
    /// An [`Result<Connection>`] representing the current database connection.
    ///
    /// # Examples
    /// ```no_run
    /// use crabapple::{Backup, Authentication};
    ///
    /// let backup = Backup::open(
    ///     "/path/to/backup",
    ///     &Authentication::Password("pass".into()),
    /// )?;
    ///
    /// let db = backup.db()?;
    /// println!("Database connection: {:?}", db);
    /// # Ok::<(), crabapple::error::BackupError>(())
    pub fn db(&self) -> Result<&Connection> {
        self.conn.as_ref().ok_or(BackupError::DatabaseClosed)
    }

    /// Query all unique domains present in the `Manifest.db`.
    ///
    /// # Arguments
    /// * `conn` - An open [`rusqlite::Connection`] to the manifest database.
    ///
    /// # Errors
    /// Returns `BackupError::Database` on query failures.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crabapple::{Backup, Authentication};
    /// use crabapple::backup::models::manifest_db;
    ///
    /// let backup = Backup::open(
    ///     "/path/to/backup",
    ///     &Authentication::Password("pass".into())
    /// )?;
    ///
    /// let domains = backup.manifest_db.query_all_domains()?;
    /// println!("Domains: {:?}", domains);
    /// # Ok::<(), crabapple::error::BackupError>(())
    /// ```
    pub fn query_all_domains(&self) -> Result<HashSet<String>> {
        let mut stmt = self.db()?.prepare(
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
        let mut domains = HashSet::new();
        while let Some(row) = rows.next()? {
            domains.insert(row.get(0)?);
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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crabapple::{Backup, Authentication};
    /// use crabapple::backup::models::manifest_db;
    ///
    /// let backup = Backup::open(
    ///     "/path/to/backup",
    ///     &Authentication::Password("pass".into())
    /// )?;
    ///
    /// let entries = backup.manifest_db.query_all_entries()?;
    /// println!("File count: {}", entries.len());
    /// # Ok::<(), crabapple::error::BackupError>(())
    /// ```
    pub fn query_all_entries(&self) -> Result<Vec<BackupFileEntry>> {
        let mut stmt = self
            .db()?
            .prepare("SELECT rowid, fileID, domain, relativePath, flags, file FROM Files")?;
        let mut rows = stmt.query([])?;
        let mut entries = Vec::new();
        while let Some(row) = rows.next()? {
            let file_id = row.get(0)?;

            let blob = self
                .db()?
                .blob_open(rusqlite::DatabaseName::Main, "Files", "file", file_id, true)
                .map_err(BackupError::Database)?;

            let plist = Value::from_reader(blob).map_err(|_| {
                BackupError::PlistParseError("Failed to parse `file` plist".to_string())
            })?;

            let mbfile = MBFile::from_plist(&plist).map_err(|_| {
                BackupError::PlistParseError("Failed to parse `MBFile` from plist".to_string())
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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crabapple::{Backup, Authentication};
    /// use crabapple::backup::models::manifest_db;
    ///
    /// let backup = Backup::open(
    ///     "/path/to/backup",
    ///     &Authentication::Password("pass".into())
    /// )?;
    ///
    /// if let Some(entry) = backup.manifest_db.query_file_by_id("fileid")? {
    ///     println!("Found file: {}", entry.file_id);
    /// }
    /// # Ok::<(), crabapple::error::BackupError>(())
    /// ```
    pub fn query_file_by_id(&self, path: &str) -> Result<Option<BackupFileEntry>> {
        // Path in DB is typically Domain-RelativePath
        let mut stmt = self.db()?.prepare(
            "SELECT rowid, fileID, domain, relativePath, flags, file FROM Files WHERE fileID = ?",
        )?;
        let mut rows = stmt.query([path])?;
        if let Some(row) = rows.next()? {
            let file_id = row.get(0)?;

            let blob = self
                .db()?
                .blob_open(rusqlite::DatabaseName::Main, "Files", "file", file_id, true)
                .map_err(BackupError::Database)?;

            let plist = Value::from_reader(blob).map_err(|_| {
                BackupError::InvalidTlvData("Failed to parse file plist".to_string())
            })?;

            let mbfile = MBFile::from_plist(&plist).map_err(|_| {
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
}

impl Drop for ManifestDb {
    fn drop(&mut self) {
        if self.is_temporary {
            if let Some(conn) = self.conn.take() {
                conn.close().ok();

                // Remove the file, ignoring errors if any
                if let Err(e) = remove_file(&self.db_path) {
                    eprintln!(
                        "warning: failed to remove temporary `Manifest.db` file at {}: {}",
                        self.db_path.display(),
                        e
                    );
                }
            }
        }
    }
}
