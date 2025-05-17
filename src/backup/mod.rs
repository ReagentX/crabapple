//! Data structures and logic for iOS backup handling

pub mod crypto;
pub mod device;
pub mod manifest_db;
pub mod models;
pub mod util;

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crypto::aes_kw_unwrap_bytes;
use manifest_db::ManifestDb;
use models::file::BackupFileEntry;
use models::manifest_data::database::DecryptedManifestDb;
use models::manifest_data::lockdown::ManifestLockdownInfo;
use models::manifest_data::manifest::{Manifest, ManifestData};
use util::hex::{hex_decode, hex_encode};

use crate::Authentication;
use crate::error::{BackupError, Result};

use self::crypto::{
    aes_decrypt_cbc_with_padding, derive_key_from_password, unlock_keys_from_manifest,
    unwrap_key_for_class,
};

/// Main entry point for working with an iOS backup.
///
/// Provides methods to initialize, configure, and extract data from a backup,
/// including metadata loading, manifest database access, and file decryption.
pub struct Backup {
    /// Filesystem path to the specific device backup folder.
    pub backup_path: PathBuf,
    /// Parsed manifest and decryption state.
    pub manifest_data: ManifestData,
    /// Decrypted manifest database handle, if available.
    decrypted_manifest_db: Option<DecryptedManifestDb>,
}

impl Backup {
    /// Create a new `MobileBackup` instance, loading manifest data.
    ///
    /// # Arguments
    ///
    /// * `backup_path` - Filesystem path to a specific device backup folder (the UDID directory).
    /// * `auth` - `BackupAuth` specifying password or derived key.
    ///
    /// # Errors
    /// Returns `BackupError` if paths are invalid, manifest loading fails, or decryption fails.
    pub fn new<P: AsRef<Path>>(backup_path: P, auth: Authentication) -> Result<Self> {
        let device_backup_path = backup_path.as_ref().to_path_buf();
        if !device_backup_path.is_dir() {
            return Err(BackupError::InvalidBackupRoot(
                device_backup_path.display().to_string(),
            ));
        }

        let manifest_plist = device_backup_path.join("Manifest.plist");

        // Ensure that the manifest plist file exists
        if !manifest_plist.exists() {
            return Err(BackupError::ManifestPlistNotFound(
                device_backup_path
                    .join("Manifest.plist")
                    .display()
                    .to_string(),
            ));
        }

        // 1. Load Manifest.plist and extract necessary keys and info
        let manifest = Manifest::load(&manifest_plist)?;

        let (main_decryption_key_opt, unlocked_class_keys_opt) = if manifest.is_encrypted {
            let bkb = manifest.backup_key_bag.as_ref().ok_or_else(|| {
                BackupError::MissingPlistKey(
                    "BackupKeyBag (required for encrypted backup)".to_string(),
                )
            })?;

            let main_derived_key = match auth {
                Authentication::Password(ref password) => derive_key_from_password(
                    password.as_bytes(),
                    &bkb.dpsl,
                    bkb.dpic,
                    &bkb.salt,
                    bkb.iter,
                )?,
                Authentication::DerivedKey(ref key_hex) => hex_decode(key_hex)?,
            };

            let unlocked_keys_map = unlock_keys_from_manifest(&main_derived_key, &manifest)?;
            (Some(main_derived_key), Some(unlocked_keys_map))
        } else {
            // For unencrypted backups, password/key should ideally not be provided or be empty.
            // This logic can be refined based on desired strictness.
            // For now, just ensuring no decryption attempts are made.
            (None, None)
        };

        let manifest_data = ManifestData {
            manifest, // Now contains the backup_date
            main_decryption_key: main_decryption_key_opt.clone(),
            unlocked_class_keys: unlocked_class_keys_opt.clone(),
        };

        // 3. Decrypt and process Manifest.db
        // Convert ByteBuf to &[u8] by using as_ref().map()
        let manifest_key_ref = manifest_data
            .manifest
            .manifest_key
            .as_ref()
            .map(std::convert::AsRef::as_ref);

        let manifest_db_obj = ManifestDb::new(
            &device_backup_path.join("Manifest.db"),
            manifest_data.manifest.is_encrypted,
            manifest_key_ref,
            &manifest_data.unlocked_class_keys,
        )?;

        Ok(Self {
            backup_path: device_backup_path,
            manifest_data,
            decrypted_manifest_db: Some(manifest_db_obj.into_decrypted_db_info()),
        })
    }

    /// Returns the current device `UDID` (the backup folder name).
    ///
    /// # Errors
    /// Returns `BackupError::InvalidBackupRoot` if the `UDID` cannot be retrieved as a string.
    pub fn udid(&self) -> Result<&str> {
        self.backup_path
            .file_name()
            .and_then(|os| os.to_str())
            .ok_or_else(|| BackupError::InvalidBackupRoot(self.backup_path.display().to_string()))
    }

    /// Returns device metadata from `Manifest.plist`.
    #[must_use]
    pub fn lockdown(&self) -> &ManifestLockdownInfo {
        &self.manifest_data.manifest.lockdown
    }

    /// Indicates whether the backup is encrypted.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.manifest_data.manifest.is_encrypted
    }

    /// Returns the main decryption key as a hex string, if the backup is encrypted.
    #[must_use]
    pub fn get_decryption_key_hex(&self) -> Option<String> {
        self.manifest_data
            .main_decryption_key
            .as_ref()
            .map(|v| hex_encode(v))
    }

    /// Get all of the domains in the backup.
    pub fn query_all_domains(&self) -> Result<Vec<String>> {
        let db_info = self
            .decrypted_manifest_db
            .as_ref()
            .ok_or(BackupError::ManifestDbNotFound)?;

        let conn = db_info.try_get_connection()?;
        manifest_db::query_all_domains(&conn)
    }

    /// List all files recorded in `Manifest.db`.
    ///
    /// # Errors
    /// Returns `BackupError` if the database cannot be accessed.
    pub fn get_backup_files_list(&self) -> Result<Vec<BackupFileEntry>> {
        let db_info = self
            .decrypted_manifest_db
            .as_ref()
            .ok_or(BackupError::ManifestDbNotFound)?;

        let conn = db_info.try_get_connection()?;
        manifest_db::query_all_files(&conn)
    }

    /// Decrypt and return the contents of a file in the backup.
    ///
    /// # Arguments
    /// * `file_id` - The unique identifier of the file to decrypt (`SHA1` hash).
    ///
    /// # Returns
    /// Plaintext data as a byte vector, decrypted if encrypted.
    ///
    /// # Errors
    /// Returns [`BackupError::FileNotFoundInBackup`] if the file ID is not found,
    /// or [`BackupError::Io`] for I/O or decryption failures.
    pub fn get_file_decrypted_copy(&self, file_id: &str) -> Result<Vec<u8>> {
        let db_info = self
            .decrypted_manifest_db
            .as_ref()
            .ok_or(BackupError::ManifestDbNotFound)?;

        let conn = db_info.try_get_connection()?;
        let file_entry = manifest_db::query_file_by_id(&conn, file_id)?
            .ok_or_else(|| BackupError::FileNotFoundInBackup(file_id.to_string()))?;

        let source_file_path = self
            .backup_path
            .join(&file_entry.file_id[0..2])
            .join(&file_entry.file_id);

        let mut db_bytes = File::open(source_file_path)?;
        let mut file_data = Vec::new();
        db_bytes.read_to_end(&mut file_data)?;

        if let Some(encryption_key) = file_entry.metadata.encryption_key {
            // TODO: Abstract this as a function like `decrypt_file()` somewhere
            let protection_class = file_entry.metadata.protection_class;
            let (_, key_bytes) = encryption_key.split_at(4);

            let class_key_entry = self
                .manifest_data
                .unlocked_class_keys
                .as_ref()
                .and_then(|keys| keys.get(&protection_class))
                .ok_or_else(|| {
                    BackupError::Crypto(
                        "Class {protection_class} key not found, needed to decrypt file key"
                            .to_string(),
                    )
                })?;

            let file_key = aes_kw_unwrap_bytes(&class_key_entry.key, key_bytes)
                .map_err(|_| BackupError::KeyUnwrapFailed(class_key_entry.class_id))?;

            let plaintext = aes_decrypt_cbc_with_padding(&file_data, &file_key)?;
            Ok(plaintext)
        } else {
            Ok(file_data)
        }
    }

    /// Get the filesystem path to the decrypted (or raw) `Manifest.db` file.
    pub fn get_manifest_db(&self) -> Result<PathBuf> {
        let info = self
            .decrypted_manifest_db
            .as_ref()
            .ok_or(BackupError::ManifestDbNotFound)?;
        Ok(info.db_path.clone())
    }

    /// Retrieve the raw 32-byte decryption key, if available.
    #[must_use]
    pub fn get_decryption_key(&self) -> Option<Vec<u8>> {
        self.manifest_data.main_decryption_key.clone()
    }

    /// Access parsed `Manifest.plist` metadata.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest_data.manifest
    }

    /// Decrypt the file represented by [`BackupFileEntry`], returning plaintext bytes.
    ///
    /// # Arguments
    /// * `entry` - A [`BackupFileEntry`] containing metadata and encrypted file ID.
    ///
    /// # Returns
    /// Plaintext data as a byte vector.
    ///
    /// # Errors
    /// Returns [`BackupError::Crypto`] on decryption errors or missing keys.
    pub fn decrypt_entry(&self, entry: &BackupFileEntry) -> Result<Vec<u8>> {
        let source = self
            .backup_path
            .join(&entry.file_id[0..2])
            .join(&entry.file_id);
        let data = std::fs::read(&source)?;
        if self.is_encrypted() {
            let class_key_entry = self
                .manifest_data
                .unlocked_class_keys
                .as_ref()
                .and_then(|keys| keys.get(&entry.metadata.protection_class)) // Class 4
                .ok_or_else(|| {
                    BackupError::Crypto(format!(
                        "Class {} key not found, needed to decrypt {} key",
                        entry.metadata.protection_class, entry.file_id
                    ))
                })?;
            let wrapped_key = &class_key_entry.key;
            let keys = self
                .manifest_data
                .unlocked_class_keys
                .as_ref()
                .ok_or_else(|| {
                    BackupError::Crypto("Missing class keys for encrypted backup".to_string())
                })?;
            let key = unwrap_key_for_class(entry.metadata.protection_class, wrapped_key, keys)?;
            aes_decrypt_cbc_with_padding(&data, &key)
        } else {
            Ok(data)
        }
    }

    /// List unique protection domains present in the backup.
    pub fn list_domains(&self) -> Result<std::collections::HashSet<String>> {
        let files = self.get_backup_files_list()?;
        let domains = files.into_iter().map(|e| e.domain).collect();
        Ok(domains)
    }

    /// Open and return a rusqlite [`rusqlite::Connection`] to the decrypted (or raw) `Manifest.db`.
    ///
    /// # Errors
    /// Returns [`BackupError::ManifestDbNotFound` ]if the database info is missing.
    pub fn manifest_connection(&self) -> Result<rusqlite::Connection> {
        let info = self
            .decrypted_manifest_db
            .as_ref()
            .ok_or(BackupError::ManifestDbNotFound)?;
        info.try_get_connection()
    }
}
