//! Module for loading, decrypting, and querying the `Manifest.db` of an iOS backup.
use std::{collections::HashSet, fs::File, io::copy, path::Path};

use plist::Value;
use rusqlite::Connection;

use crate::{
    backup::{
        crypto::{aes_decrypt_cbc_reader, aes_kw_unwrap_bytes},
        models::{
            file::{BackupFileEntry, MBFile},
            manifest_data::database::DecryptedManifestDb,
            manifest_data::manifest::ManifestData,
        },
        util::hex::hex_encode,
    },
    error::{BackupError, Result},
};

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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crabapple::{Backup, Authentication};
    /// use crabapple::backup::manifest_db::ManifestDb;
    /// use std::path::Path;
    ///
    /// let backup = Backup::new(
    ///     Path::new("/path/to/backup"),
    ///     &Authentication::Password("pass".into())
    /// ).unwrap();
    ///
    /// let db_path = backup.get_manifest_db_path();
    /// ```
    pub fn new(db_path: &Path, manifest_data: &ManifestData) -> Result<Self> {
        if !db_path.exists() {
            return Err(BackupError::ManifestDbNotFound);
        }

        let decrypted_db_info = if manifest_data.manifest.is_encrypted {
            let manifest_key_bytes =
                manifest_data
                    .manifest
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
            // TODO: this is repeated in `Backup::get_file_decrypted_copy`, clean it up
            let (class_bytes, key_bytes) = manifest_key_bytes.split_at(4);
            let manifest_class = u32::from_le_bytes(class_bytes.try_into().unwrap());

            let class_key_entry = manifest_data.get_class_key(manifest_class)?;

            let key = aes_kw_unwrap_bytes(&class_key_entry.key, key_bytes)
                .map_err(|_| BackupError::KeyUnwrapFailed(manifest_class))?;

            // Decrypt the Manifest.db using the unwrapped key
            let db_bytes = File::open(db_path)?;
            let mut decrypted_manifest_db_stream = aes_decrypt_cbc_reader(&db_bytes, &key)?;

            // Write decrypted Manifest.db into the platform-specific temporary directory
            let tmp_path = std::env::temp_dir().join("crabapple-Manifest.db");
            let mut file = File::create(&tmp_path)?;

            // Stream-decrypt directly into the temp file
            copy(&mut decrypted_manifest_db_stream, &mut file).map_err(|e| {
                BackupError::Crypto(format!("Failed writing decrypted Manifest.db: {}", e))
            })?;

            DecryptedManifestDb {
                db_path: tmp_path,
                is_temporary: true,
                connection_string: db_path.to_string_lossy().into_owned(), // Path for direct open
                decryption_key: Some(hex_encode(&key)),
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
    #[must_use]
    pub(crate) fn into_decrypted_db_info(self) -> DecryptedManifestDb {
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
///
/// # Examples
///
/// ```no_run
/// use crabapple::{Backup, Authentication};
/// use crabapple::backup::manifest_db;
/// use std::path::Path;
///
/// let backup = Backup::new(
///     Path::new("/path/to/backup"),
///     &Authentication::Password("pass".into())
/// ).unwrap();
///
/// let domains = manifest_db::query_all_domains(&backup.db).unwrap();
/// println!("Domains: {:?}", domains);
/// ```
pub fn query_all_domains(conn: &Connection) -> Result<HashSet<String>> {
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
/// use crabapple::backup::manifest_db;
/// use std::path::Path;
///
/// let backup = Backup::new(
///     Path::new("/path/to/backup"),
///     &Authentication::Password("pass".into())
/// ).unwrap();
///
/// let files = manifest_db::query_all_files(&backup.db).unwrap();
/// println!("File count: {}", files.len());
/// ```
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
///
/// # Examples
///
/// ```no_run
/// use crabapple::{Backup, Authentication};
/// use crabapple::backup::manifest_db;
/// use std::path::Path;
///
/// let backup = Backup::new(
///     Path::new("/path/to/backup"),
///     &Authentication::Password("pass".into())
/// ).unwrap();
///
/// if let Some(entry) = manifest_db::query_file_by_id(&backup.db, "fileid").unwrap() {
///     println!("Found file: {}", entry.file_id);
/// }
/// ```
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
