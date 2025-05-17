//! Holds information for opening a backup's `Manifest.db`

use std::path::PathBuf;

use crate::error::{BackupError, Result};

/// Holds information for opening a backup's `Manifest.db`, including file path and optional `SQLCipher` key.
#[derive(Debug, Clone)]
pub struct DecryptedManifestDb {
    /// Path to the `SQLite` database file.
    pub db_path: PathBuf,
    /// Whether `db_path` points to a temporary decrypted file.
    pub is_temporary: bool,
    /// Connection string (usually the file path).
    pub connection_string: String,
    /// Optional hex-encoded `SQLCipher` key to use when opening.
    pub decryption_key: Option<String>,
}

impl DecryptedManifestDb {
    /// Open a `SQLite` connection to the manifest database.
    ///
    /// # Returns
    /// A [`rusqlite::Connection`] to the database file specified by `db_path`.
    ///
    /// # Errors
    /// Returns [`BackupError::Database`] if opening the connection fails.
    pub fn try_get_connection(&self) -> Result<rusqlite::Connection> {
        rusqlite::Connection::open(&self.db_path).map_err(BackupError::Database)
    }
}
