//! `Manifest.plist` representation and parsing.

use std::{collections::HashMap, fs::File, path::Path};

use plist::Value;

use crate::{
    backup::{
        models::{
            keyring::{EncryptionKey, KeyRing, ProtectionClassKey},
            manifest::lockdown::ManifestLockdownInfo,
        },
        util::plist::{get_key_as_boolean, get_key_as_data},
    },
    error::{BackupError, Result},
};

/// Holds in-memory parsed manifest (`Manifest.plist`) and associated decryption key and unwrapped class keys.
///
/// # Examples
///
/// ```no_run
/// use crabapple::backup::models::manifest::manifest_plist::{Manifest, ManifestData};
/// use std::path::Path;
///
/// // Load the manifest
/// let path = Path::new("/path/to/Manifest.plist");
/// let data = ManifestData::load(path).unwrap();
/// let manifest = Manifest { manifest_data: data, main_decryption_key: None, unlocked_class_keys: None };
/// // For unencrypted backups, no keys are present
/// assert!(!manifest.manifest_data.is_encrypted);
/// ```
#[derive(Debug, Clone)]
pub struct Manifest {
    /// Parsed `Manifest.plist` data.
    pub manifest_data: ManifestData,
    /// Derived decryption key (`32` bytes) if encrypted.
    pub main_decryption_key: Option<EncryptionKey>,
    /// Unwrapped per-class keys after decryption.
    pub unlocked_class_keys: Option<HashMap<u32, ProtectionClassKey>>,
}

impl Manifest {
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
    pub fn keys(&self) -> Result<&HashMap<u32, ProtectionClassKey>> {
        self.unlocked_class_keys.as_ref().ok_or_else(|| {
            BackupError::Crypto("Missing class keys for encrypted backup".to_string())
        })
    }
}

/// Parsed data from `Manifest.plist` describing the backup.
#[derive(Debug, Clone)]
pub struct ManifestData {
    /// Optional key bag containing encrypted class keys.
    pub key_ring: Option<KeyRing>,
    /// Whether the backup is encrypted.
    pub is_encrypted: bool,
    /// Device-specific lockdown info.
    pub lockdown: ManifestLockdownInfo,
    /// Optional raw manifest key (typically 40 bytes) used for Manifest.db decryption.
    pub manifest_key: Option<EncryptionKey>,
}

impl ManifestData {
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
    /// use crabapple::backup::models::manifest::manifest_plist::ManifestData;
    /// use std::path::Path;
    ///
    /// let data = ManifestData::load(Path::new("/path/to/Manifest.plist")).unwrap();
    /// println!("Encrypted: {}", data.is_encrypted);
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
        let backup_key_ring = if is_encrypted {
            let data = get_key_as_data(dict, "BackupKeyBag")?;
            Some(KeyRing::from_bytes(&data)?)
        } else {
            None
        };
        let manifest_key = if is_encrypted {
            let data = get_key_as_data(dict, "ManifestKey")?;
            Some(data.clone().into())
        } else {
            None
        };
        let lockdown_val = dict
            .get("Lockdown")
            .ok_or_else(|| BackupError::MissingPlistKey("Lockdown".into()))?;
        let lockdown = ManifestLockdownInfo::from_plist(lockdown_val)?;
        Ok(ManifestData {
            key_ring: backup_key_ring,
            is_encrypted,
            lockdown,
            manifest_key,
        })
    }
}
