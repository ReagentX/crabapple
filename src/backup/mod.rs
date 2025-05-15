//! Data structures and logic for iOS backup handling

pub mod crypto;
pub mod device;
pub mod manifest_db;
pub mod types;
pub mod util;

use std::fs;
use std::path::{Path, PathBuf};

use self::types::{BackupAuth, BackupFileEntry, DecryptedManifestDb, Manifest, ManifestData};
use crate::error::{BackupError, Result};

use self::crypto::{
    aes_decrypt_cbc_with_padding, derive_key_from_password, unlock_keys_from_manifest,
    unwrap_key_for_class,
};
use self::manifest_db::ManifestDb;

/// Main entry point for working with an iOS backup.
///
/// Provides methods to initialize, configure, and extract data from a backup,
/// including metadata loading, manifest database access, and file decryption.
pub struct Backup {
    /// Filesystem path to the specific device backup folder.
    backup_path: PathBuf,
    /// Parsed manifest and decryption state.
    manifest_data: ManifestData,
    /// Decrypted manifest database handle, if available.
    decrypted_manifest_db: Option<DecryptedManifestDb>,
}

impl Backup {
    /// Create a new `MobileBackup` instance, loading manifest data.
    ///
    /// # Arguments
    ///
    /// * `backup_path` - Filesystem path to a specific device backup folder (the UDID directory).
    /// * `auth` - BackupAuth specifying password or derived key.
    ///
    /// # Errors
    /// Returns `BackupError` if paths are invalid, manifest loading fails, or decryption fails.
    pub fn new<P: AsRef<Path>>(backup_path: P, auth: BackupAuth) -> Result<Self> {
        let device_backup_path = backup_path.as_ref().to_path_buf();
        if !device_backup_path.is_dir() {
            return Err(BackupError::InvalidBackupRoot(
                device_backup_path.display().to_string(),
            ));
        }

        let manifest_plist = device_backup_path.join("Manifest.plist");
        if !manifest_plist.exists() {
            return Err(BackupError::ManifestPlistNotFound(
                device_backup_path
                    .join("Manifest.plist")
                    .display()
                    .to_string(),
            ));
        }

        let plist_modification_time = fs::metadata(&manifest_plist)?.modified()?;
        let backup_date = chrono::DateTime::<chrono::Utc>::from(plist_modification_time);

        // 1. Load Manifest.plist and extract necessary keys and info
        // This call now correctly uses types::PlistInfo::load, as PlistInfo is imported from self::types
        println!("Loading Manifest.plist...");
        let mut manifest = Manifest::load(&manifest_plist)?;
        manifest.backup_date = Some(backup_date); // Set the backup date from file metadata

        let (main_decryption_key_opt, unlocked_class_keys_opt) = if manifest.is_encrypted {
            let bkb = manifest.backup_key_bag.as_ref().ok_or_else(|| {
                BackupError::MissingPlistKey(
                    "BackupKeyBag (required for encrypted backup)".to_string(),
                )
            })?;

            let main_derived_key = match auth {
                BackupAuth::Password(ref password) => {
                    derive_key_from_password(password.as_bytes(), &bkb.dpsl, bkb.dpic, &bkb.salt, bkb.iter)?
                }
                BackupAuth::DerivedKey(ref key_hex) => util::hex_decode(key_hex)?,
            };

            println!("Derived key: {:?}", main_derived_key);

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

        println!("Manifest data: {:?}", manifest_data);

        // 3. Decrypt and process Manifest.db
        // Convert ByteBuf to &[u8] by using as_ref().map()
        let manifest_key_ref = manifest_data.manifest.manifest_key.as_ref().map(|buf| buf.as_ref());
        
        let manifest_db_obj = ManifestDb::new(
            &device_backup_path.join("Manifest.db"),
            manifest_data.manifest.is_encrypted,
            manifest_key_ref,
            &manifest_data.unlocked_class_keys,
            &device_backup_path,
        )?;

        Ok(Self {
            backup_path: device_backup_path,
            manifest_data,
            decrypted_manifest_db: Some(manifest_db_obj.into_decrypted_db_info()),
        })
    }

    /// Returns the current device UDID.
    pub fn udid(&self) -> Result<&str> {
        self.backup_path
            .file_name()
            .and_then(|os| os.to_str())
            .ok_or_else(|| BackupError::InvalidBackupRoot(self.backup_path.display().to_string()))
    }

    /// Returns the backup date from the manifest metadata, if present.
    pub fn backup_date(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.manifest_data.manifest.backup_date
    }

    /// Returns device metadata from `Manifest.plist`.
    pub fn device_info(&self) -> &types::ManifestLockdownInfo {
        &self.manifest_data.manifest.lockdown
    }

    /// Indicates whether the backup is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.manifest_data.manifest.is_encrypted
    }

    /// Returns the main decryption key as a hex string, if the backup is encrypted.
    pub fn get_decryption_key_hex(&self) -> Option<String> {
        self.manifest_data
            .main_decryption_key
            .as_ref()
            .map(|v| util::hex_encode(v))
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
    /// * `domain` - Protection domain for the file (not currently used in path lookup).
    /// * `relative_path` - The file's path within the backup catalog.
    ///
    /// # Returns
    /// File data as a byte vector.
    ///
    /// # Errors
    /// Returns `BackupError` if lookup, decryption, or I/O fails.
    pub fn get_file_decrypted_copy(&self, _domain: &str, relative_path: &str) -> Result<Vec<u8>> {
        let db_info = self
            .decrypted_manifest_db
            .as_ref()
            .ok_or(BackupError::ManifestDbNotFound)?;

        let conn = db_info.try_get_connection()?;
        let file_entry = manifest_db::query_file_by_path(&conn, relative_path)?
            .ok_or_else(|| BackupError::FileNotFoundInBackup(relative_path.to_string()))?;

        let source_file_path = self
            .backup_path
            .join(&file_entry.file_id[0..2])
            .join(&file_entry.file_id);

        let file_data = fs::read(&source_file_path)?;
        if self.is_encrypted() {
            let protection_class = file_entry.protection_class;
            let wrapped_key = file_entry.encryption_key_wrapped.as_ref().ok_or_else(|| {
                BackupError::Crypto(format!(
                    "File {} (class {}) is encrypted but no wrapped key found",
                    relative_path, protection_class
                ))
            })?;
            let unlocked_keys =
                self.manifest_data
                    .unlocked_class_keys
                    .as_ref()
                    .ok_or_else(|| {
                        BackupError::Crypto(
                            "Unlocked class keys missing for encrypted backup".to_string(),
                        )
                    })?;
            let file_key = unwrap_key_for_class(protection_class, wrapped_key, unlocked_keys)?;
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
    pub fn get_decryption_key(&self) -> Option<Vec<u8>> {
        self.manifest_data.main_decryption_key.clone()
    }

    /// Access parsed `Manifest.plist` metadata.
    pub fn plist_info(&self) -> &Manifest {
        &self.manifest_data.manifest
    }

    /// Decrypt a file based on its catalog entry.
    pub fn decrypt_entry(&self, entry: &BackupFileEntry) -> Result<Vec<u8>> {
        let source = self
            .backup_path
            .join(&entry.file_id[0..2])
            .join(&entry.file_id);
        let data = std::fs::read(&source)?;
        if self.is_encrypted() {
            let wrapped = entry.encryption_key_wrapped.as_ref().ok_or_else(|| {
                BackupError::Crypto(format!("No wrapped key for file {}", entry.relative_path))
            })?;
            let keys = self
                .manifest_data
                .unlocked_class_keys
                .as_ref()
                .ok_or_else(|| {
                    BackupError::Crypto("Missing class keys for encrypted backup".to_string())
                })?;
            let key = unwrap_key_for_class(entry.protection_class, wrapped, keys)?;
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

    /// Open a rusqlite `Connection` to the decrypted (or raw) Manifest.db.
    pub fn manifest_connection(&self) -> Result<rusqlite::Connection> {
        let info = self
            .decrypted_manifest_db
            .as_ref()
            .ok_or(BackupError::ManifestDbNotFound)?;
        info.try_get_connection()
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{Backup, BackupAuth};

    #[test]
    fn test_run() {
        let backup_path = Path::new(
            "/Users/chris/Library/Application Support/MobileSync/Backup/00008110-001458313A22801E",
        );
        print!("Backup path: {:?}", backup_path);
        let auth = BackupAuth::Password("science".to_string());
        let backup = Backup::new(backup_path, auth);
        match backup {
            Ok(_) => println!("Backup resolved successfully"),
            Err(e) => panic!("Failed to read backup: {:?}", e),
        };
        backup.unwrap().get_backup_files_list().unwrap();
    }
}
