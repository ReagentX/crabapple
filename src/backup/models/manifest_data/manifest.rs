//! Backup Manifest representation and parsing.

use plist::Value;
use std::path::Path;
use std::{collections::HashMap, fs::File};

use crate::backup::models::keyring::{BackupKeyBag, ProtectionClassKey};
use crate::backup::util::plist::{get_key_as_boolean, get_key_as_data};
use crate::error::{BackupError, Result};

use super::lockdown::ManifestLockdownInfo;

/// Holds in-memory parsed manifest (`Manifest.plist`) and associated decryption key and unwrapped class keys.
///
/// # Examples
///
/// ```no_run
/// use crabapple::backup::models::manifest_data::{Manifest, ManifestData};
/// use std::path::Path;
///
/// // Load the manifest
/// let path = Path::new("/path/to/Manifest.plist");
/// let manifest = Manifest::load(path).unwrap();
/// let data = ManifestData { manifest, main_decryption_key: None, unlocked_class_keys: None };
/// // For unencrypted backups, no keys are present
/// assert!(!data.manifest.is_encrypted);
/// ```
#[derive(Debug, Clone)]
pub struct ManifestData {
    /// Parsed `Manifest.plist` data.
    pub manifest: Manifest,
    /// Derived decryption key (`32` bytes) if encrypted.
    pub main_decryption_key: Option<Vec<u8>>,
    /// Unwrapped per-class keys after decryption.
    pub unlocked_class_keys: Option<HashMap<u32, ProtectionClassKey>>,
}

impl ManifestData {
    /// Get the `ProtectionClassKey` for a given protection class.
    ///
    /// # Errors
    /// Returns [`BackupError::Crypto`] if class key not found.
    pub fn get_class_key(&self, protection_class: u32) -> Result<&ProtectionClassKey> {
        self.unlocked_class_keys
            .as_ref()
            .and_then(|keys| keys.get(&protection_class))
            .ok_or_else(|| BackupError::Crypto(format!("Class {protection_class} key not found!",)))
    }

    /// Get all decryption keys for the manifest.
    ///
    /// # Errors
    /// Returns [`BackupError::Crypto`] if no class keys available.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crabapple::backup::models::manifest_data::ManifestData;
    ///
    /// let keys = data.keys().unwrap();
    /// for (cid, key) in keys {
    ///     println!("Class {} key length {}", cid, key.key.len());
    /// }
    /// ```
    pub fn keys(&self) -> Result<&HashMap<u32, ProtectionClassKey>> {
        self.unlocked_class_keys.as_ref().ok_or_else(|| {
            BackupError::Crypto("Missing class keys for encrypted backup".to_string())
        })
    }
}

/// Parsed data from `Manifest.plist` describing the backup.
#[derive(Debug, Clone)]
pub struct Manifest {
    /// Optional key bag containing encrypted class keys.
    pub backup_key_bag: Option<BackupKeyBag>,
    /// Whether the backup is encrypted.
    pub is_encrypted: bool,
    /// Device-specific lockdown info.
    pub lockdown: ManifestLockdownInfo,
    /// Optional raw manifest key (typically 40 bytes) used for Manifest.db decryption.
    pub manifest_key: Option<Vec<u8>>,
}

impl Manifest {
    /// Load and parse the backup's `Manifest.plist` file.
    ///
    /// Returns a [`Manifest`] struct containing metadata and encryption parameters.
    ///
    /// # Arguments
    ///
    /// * `path` - Filesystem path to the `Manifest.plist` file.
    ///
    /// # Errors
    /// Returns [`BackupError::ManifestPlistNotFound`] if file missing, or other errors if parse fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crabapple::backup::models::manifest_data::Manifest;
    /// use std::path::Path;
    ///
    /// let manifest = Manifest::load(Path::new("/path/to/Manifest.plist")).unwrap();
    /// println!("Encrypted: {}", manifest.is_encrypted);
    /// ```
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();
        let file = File::open(path_ref)
            .map_err(|_| BackupError::ManifestPlistNotFound(path_ref.display().to_string()))?;
        let plist = Value::from_reader(file)?;
        let dict = plist.as_dictionary().ok_or_else(|| {
            BackupError::PlistParseError("Top-level plist is not a dictionary".into())
        })?;
        let is_encrypted = get_key_as_boolean(dict, "IsEncrypted").unwrap_or(false);
        let backup_key_bag = if is_encrypted {
            let data = get_key_as_data(dict, "BackupKeyBag")?;
            Some(BackupKeyBag::from_bytes(&data))
        } else {
            None
        };
        let manifest_key = if is_encrypted {
            let data = get_key_as_data(dict, "ManifestKey")?;
            Some(data.clone())
        } else {
            None
        };
        let lockdown_val = dict
            .get("Lockdown")
            .ok_or_else(|| BackupError::MissingPlistKey("Lockdown".into()))?;
        let lockdown = ManifestLockdownInfo::from_plist(lockdown_val)?;
        Ok(Manifest {
            backup_key_bag,
            is_encrypted,
            lockdown,
            manifest_key,
        })
    }
}
