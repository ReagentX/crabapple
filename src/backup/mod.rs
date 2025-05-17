//! Data structures and logic for iOS backup handling

pub mod crypto;
pub mod device;
pub mod manifest_db;
pub mod models;
pub(crate) mod util;

use std::{
    collections::HashSet,
    fs::{File, read},
    io::BufReader,
    path::{Path, PathBuf},
};

use rusqlite::Connection;

use crate::{
    backup::{
        crypto::{
            aes_decrypt_cbc_with_padding, aes_kw_unwrap_bytes, derive_key_from_password,
            unlock_keys_from_manifest,
        },
        manifest_db::ManifestDb,
        models::{
            auth::Authentication,
            file::BackupFileEntry,
            manifest_data::{
                database::DecryptedManifestDb,
                lockdown::ManifestLockdownInfo,
                manifest::{Manifest, ManifestData},
            },
        },
        util::hex::{hex_decode, hex_encode},
    },
    error::{BackupError, Result},
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
    decrypted_manifest_db: DecryptedManifestDb,
    /// Connection to the manifest database
    pub db: Connection,
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
    /// Returns [`BackupError`] if paths are invalid, manifest loading fails, or decryption fails.
    pub fn new<P: AsRef<Path>>(backup_path: P, auth: &Authentication) -> Result<Self> {
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

        // Load Manifest.plist and extract necessary keys and info
        let manifest = Manifest::load(&manifest_plist)?;

        let (main_decryption_key_opt, unlocked_class_keys_opt) = if manifest.is_encrypted {
            let backup_key_bag = manifest.backup_key_bag.as_ref().ok_or_else(|| {
                BackupError::MissingPlistKey(
                    "BackupKeyBag (required for encrypted backup)".to_string(),
                )
            })?;

            let main_derived_key = match auth {
                Authentication::Password(password) => derive_key_from_password(
                    password.as_bytes(),
                    &backup_key_bag.dpsl,
                    backup_key_bag.dpic,
                    &backup_key_bag.salt,
                    backup_key_bag.iter,
                )?,
                Authentication::DerivedKey(key_hex) => hex_decode(key_hex)?,
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

        let manifest_db_obj =
            ManifestDb::new(&device_backup_path.join("Manifest.db"), &manifest_data)?;

        // Create a connection to the manifest database
        let mdb = manifest_db_obj.into_decrypted_db_info();
        let conn = mdb.try_get_connection()?;

        Ok(Self {
            backup_path: device_backup_path,
            manifest_data,
            decrypted_manifest_db: mdb,
            db: conn,
        })
    }

    /// Returns the current device `UDID` (the backup folder name).
    ///
    /// # Errors
    /// Returns [`BackupError::InvalidBackupRoot`] if the `UDID` cannot be retrieved as a string.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crabapple::{Backup, Authentication};
    /// use std::path::Path;
    ///
    /// let backup = Backup::new(
    ///     Path::new("/path/to/backup"),
    ///     &Authentication::Password("pass".into())
    /// ).unwrap();
    ///
    /// let udid = backup.udid().unwrap();
    /// println!("UDID: {}", udid);
    /// ```
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
    ///
    /// # Returns
    /// An [`Option<String>`] containing the decryption key in hexadecimal representation,
    /// or [`None`] if the backup is not encrypted.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crabapple::{Backup, Authentication};
    /// use std::path::Path;
    ///
    /// let backup = Backup::new(
    ///     Path::new("/path/to/backup"),
    ///     &Authentication::Password("pass".into())
    /// ).unwrap();
    ///
    /// if let Some(key_hex) = backup.get_decryption_key_hex() {
    ///     println!("Key: {}", key_hex);
    /// }
    /// ```
    #[must_use]
    pub fn get_decryption_key_hex(&self) -> Option<String> {
        self.manifest_data
            .main_decryption_key
            .as_ref()
            .map(|v| hex_encode(v))
    }

    /// Get all domains present in the backup's manifest database.
    ///
    /// # Returns
    /// A [`Vec<String>`] containing each unique domain present in the backup.
    ///
    /// # Errors
    /// Returns [`BackupError::ManifestDbNotFound`] if the manifest database is unavailable,
    /// or [`BackupError::Database`] if the database query fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crabapple::{Backup, Authentication};
    /// use std::path::Path;
    ///
    /// let backup = Backup::new(
    ///     Path::new("/path/to/backup"),
    ///     &Authentication::Password("pass".into())
    /// ).unwrap();
    ///
    /// let domains = backup.query_all_domains().unwrap();
    /// println!("Domains: {:?}", domains);
    /// ```
    pub fn query_all_domains(&self) -> Result<HashSet<String>> {
        manifest_db::query_all_domains(&self.db)
    }

    /// Get the filesystem path to the decrypted (or raw) `Manifest.db` file.
    ///
    /// # Returns
    /// A [`Path`] pointing to the location of the manifest database file.
    ///
    /// # Errors
    /// Returns [`BackupError::ManifestDbNotFound`] if the manifest database information is missing.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crabapple::{Backup, Authentication};
    /// use std::path::Path;
    ///
    /// let backup = Backup::new(
    ///     Path::new("/path/to/backup"),
    ///     &Authentication::Password("pass".into())
    /// ).unwrap();
    ///
    /// let db_path = backup.get_manifest_db_path();
    /// println!("Manifest.db path: {:?}", db_path);
    /// ```
    pub fn get_manifest_db_path(&self) -> &Path {
        &self.decrypted_manifest_db.db_path
    }

    /// List all files recorded in `Manifest.db`.
    ///
    /// # Errors
    /// Returns `BackupError` if the database cannot be accessed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crabapple::{Backup, Authentication};
    /// use std::path::Path;
    ///
    /// let backup = Backup::new(
    ///     Path::new("/path/to/backup"),
    ///     &Authentication::Password("pass".into())
    /// ).unwrap();
    ///
    /// let files = backup.get_backup_files_list().unwrap();
    /// for file in files {
    ///     println!("{:?}", file);
    /// }
    /// ```
    pub fn get_backup_files_list(&self) -> Result<Vec<BackupFileEntry>> {
        manifest_db::query_all_files(&self.db)
    }

    /// Get a single file entry by its file ID.
    ///
    /// # Arguments
    /// * `file_id` - The file's unique identifier (`SHA1` hash).
    ///
    /// # Errors
    /// Returns [`BackupError::FileNotFoundInBackup`] if the specified file ID is not found,
    /// or [`BackupError::Database`] if the database query fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crabapple::{Backup, Authentication};
    /// use std::path::Path;
    ///
    /// let backup = Backup::new(
    ///     Path::new("/path/to/backup"),
    ///     &Authentication::Password("pass".into())
    /// ).unwrap();
    ///
    /// let entry = backup.get_file("41ee3469300471004e6d526ebd09c051c19f8a39").unwrap();
    /// println!("File encryption key: {:?}", entry.metadata.encryption_key);
    /// ```
    pub fn get_file(&self, file_id: &str) -> Result<BackupFileEntry> {
        manifest_db::query_file_by_id(&self.db, file_id)?
            .ok_or_else(|| BackupError::FileNotFoundInBackup(file_id.to_string()))
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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crabapple::{Backup, Authentication};
    /// use std::path::Path;
    ///
    /// let backup = Backup::new(
    ///     Path::new("/path/to/backup"),
    ///     &Authentication::Password("pass".into())
    /// ).unwrap();
    ///
    /// let data = backup.decrypt_file_from_id("41ee3469300471004e6d526ebd09c051c19f8a39").unwrap();
    /// println!("Decrypted data length: {}", data.len());
    /// ```
    // TODO: Remove this?
    pub fn decrypt_file_from_id(&self, file_id: &str) -> Result<Vec<u8>> {
        let file_entry = self.get_file(file_id)?;
        self.decrypt_entry(&file_entry)
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
    // The first 4 bytes of the [`BackupFileEntry`]'s [`key`](BackupFileEntry::key) are interpreted as a little-endian
    // `u32` protection class identifier. The remainder is treated as an AES-key-wrapped
    // file key (RFC 3394).
    //
    // 1. Parse out the protection class ID.
    // 2. Look up the corresponding unwrapped class key in `class_keys`.
    // 3. Unwrap the file-specific AES key using AES-Key-Wrap.
    // 4. Decrypt `ciphertext` with AES-256-CBC (zero IV), stripping PKCS#7 padding.
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

        let data = read(&source)?;

        if let Some(encryption_key) = &entry.metadata.encryption_key {
            let (_, key_bytes) = encryption_key.get_class_key();

            let class_key_entry = self
                .manifest_data
                .get_class_key(entry.metadata.protection_class)?;

            let key = aes_kw_unwrap_bytes(&class_key_entry.key, key_bytes)
                .map_err(|_| BackupError::KeyUnwrapFailed(class_key_entry.class_id))?;

            aes_decrypt_cbc_with_padding(&data, &key)
        } else {
            Ok(data)
        }
    }

    /// Decrypt a file stream using AES-256-CBC with PKCS7 padding.
    ///
    /// # Arguments
    /// * `ciphertext` - A reader over the encrypted file bytes.
    ///
    /// # Returns
    /// A streaming reader implementing `std::io::Read` that yields plaintext as it's read.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crabapple::{Backup, Authentication};
    /// use std::{fs::File, io::copy};
    ///
    /// # fn main() -> crabapple::error::Result<()> {
    ///     let backup = Backup::new(
    ///         "/path/to/backup",
    ///         &Authentication::Password("pass".into()),
    ///     )?;
    ///    
    ///     let file = backup.get_file("41ee3469300471004e6d526ebd09c051c19f8a39")?;
    ///     let mut reader = backup.decrypt_entry_stream(&file)?;
    ///     let mut plain = Vec::new();
    ///     copy(&mut reader, &mut plain)?;
    ///     Ok(())
    /// }
    /// ```
    pub fn decrypt_entry_stream(
        &self,
        entry: &BackupFileEntry,
    ) -> Result<crypto::AesCbcDecryptReader<BufReader<File>>> {
        let ciphertext = File::open(self.backup_path.join(entry.source()))?;

        if let Some(encryption_key) = &entry.metadata.encryption_key {
            let (_, key_bytes) = encryption_key.get_class_key();

            let class_key_entry = self
                .manifest_data
                .get_class_key(entry.metadata.protection_class)?;

            let key = aes_kw_unwrap_bytes(&class_key_entry.key, key_bytes)
                .map_err(|_| BackupError::KeyUnwrapFailed(class_key_entry.class_id))?;

            return crypto::aes_decrypt_cbc_reader(ciphertext, &key);
        }
        Err(BackupError::KeyUnwrapFailed(
            entry.metadata.protection_class,
        ))
    }
}
