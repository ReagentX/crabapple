//! Type definitions for iOS backup metadata structures, authentication, and file entries.

use plist::Value;
use serde::Deserialize;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::{collections::HashMap, io::BufReader};

use serde_bytes::ByteBuf;

use crate::{
    backup::util::tlv_blocks,
    error::{BackupError, Result},
};

/// Authentication method for encrypted backups.
///
/// Use a plaintext password or provide a pre-derived encryption key (hex-encoded).
#[derive(Debug, Clone)]
pub enum Authentication {
    /// Cleartext password provided by the user.
    Password(String),
    /// Pre-derived key (hex-encoded) to decrypt backup.
    DerivedKey(String),
}

/// Parsed data from `Manifest.plist` describing the backup.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Manifest {
    /// raw CFData for BackupKeyBag
    #[serde(rename = "BackupKeyBag", with = "serde_bytes", default)]
    pub backup_key_bag_raw: Option<ByteBuf>,
    /// Optional key bag containing encrypted class keys.
    #[serde(default)]
    #[serde(skip)]
    pub backup_key_bag: Option<BackupKeyBag>,
    /// Whether the backup is encrypted.
    pub is_encrypted: bool,
    /// Device-specific lockdown info.
    pub lockdown: ManifestLockdownInfo,
    /// Optional raw manifest key (typically 40 bytes) used for Manifest.db decryption.
    #[serde(with = "serde_bytes", default)]
    pub manifest_key: Option<ByteBuf>,
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
    /// Returns [`BackupError::General`] if the file cannot be opened or parsed.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path.as_ref()).map_err(|e| {
            BackupError::PlistParseError(format!(
                "Failed to open Manifest.plist at {:?}: {}",
                path.as_ref(),
                e
            ))
        })?;

        // Deserialize directly into PlistInfo
        let mut manifest: Manifest = ::plist::from_reader(BufReader::new(file)).map_err(|e| {
            BackupError::PlistParseError(format!("Failed to parse Manifest.plist: {}", e))
        })?;

        // If encrypted, unpack that CFData blob
        if manifest.is_encrypted {
            let raw = manifest
                .backup_key_bag_raw
                .take()
                .ok_or_else(|| BackupError::MissingPlistKey("BackupKeyBag is missing".into()))?;
            let bag = BackupKeyBag::from_bytes(&raw);

            manifest.backup_key_bag = Some(bag);

            // also ensure manifest_key was present…
            if manifest.manifest_key.is_none() {
                return Err(BackupError::MissingPlistKey(
                    "ManifestKey is missing".into(),
                ));
            }
        }
        Ok(manifest)
    }
}

/// Device metadata from the backup's `Manifest.plist`.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ManifestLockdownInfo {
    /// iOS build version (e.g., "18E199").
    #[serde(rename = "BuildVersion")]
    pub build_version: String,
    /// Human-readable device name.
    #[serde(rename = "DeviceName")]
    pub device_name: String,
    /// Device product type (e.g., "iPhone9,4").
    #[serde(rename = "ProductType")]
    pub product_type: String,
    /// iOS version (e.g., "15.5").
    #[serde(rename = "ProductVersion")]
    pub product_version: String,
    /// Device serial number.
    #[serde(rename = "SerialNumber")]
    pub serial_number: String,
    /// Unique device identifier (UDID).
    #[serde(rename = "UniqueDeviceID")]
    pub unique_device_id: String,
}

#[derive(Debug, Clone)]
pub struct BackupKeyBag {
    pub bag_type: u32,
    /// Identifier for the backup key bag.
    pub uuid: Vec<u8>,
    /// Optional wrap key for certain classes.
    pub wrap: Vec<u8>,
    /// DPSL parameter for key derivation.
    pub dpsl: Vec<u8>,
    /// DPIC parameter for key derivation.
    pub dpic: u32,
    /// Salt for PBKDF2 key derivation.
    pub salt: Vec<u8>,
    /// Number of iterations for PBKDF2.
    pub iter: u32,
    /// Other attributes (e.g., "KEY", "WPKY").
    pub attrs: HashMap<[u8; 4], Vec<u8>>,
    /// Map of protection class IDs to wrapped key data.
    pub class_keys: HashMap<u32, ClassKeyData>,
}

impl BackupKeyBag {
    pub fn from_bytes(blob: &[u8]) -> BackupKeyBag {
        let mut bag = BackupKeyBag {
            bag_type: 0,
            uuid: Vec::new(),
            wrap: Vec::new(),
            dpsl: Vec::new(),
            salt: Vec::new(),
            dpic: 0,
            iter: 0,
            attrs: HashMap::new(),
            class_keys: HashMap::new(),
        };
        let mut current: Option<HashMap<[u8; 4], Vec<u8>>> = None;
        for (tag, data) in tlv_blocks(blob) {
            // if a 4‐byte value, interpret as big‐endian u32
            if data.len() == 4 {
                let v = u32::from_be_bytes(data.as_slice().try_into().unwrap());
                if &tag == b"TYPE" {
                    bag.bag_type = v;
                    continue;
                }
            }
            match &tag {
                b"UUID" if bag.uuid.is_empty() => bag.uuid = data,
                b"WRAP" if bag.wrap.is_empty() => bag.wrap = data,
                b"DPSL" if bag.dpsl.is_empty() => bag.dpsl = data,
                b"SALT" if bag.salt.is_empty() => bag.salt = data,
                b"DPIC" if bag.dpic == 0 => {
                    bag.dpic = u32::from_be_bytes(data.as_slice().try_into().unwrap());
                }
                b"ITER" if bag.iter == 0 => {
                    bag.iter = u32::from_be_bytes(data.as_slice().try_into().unwrap());
                }
                b"UUID" => {
                    // starting a new class‐key record
                    if let Some(cur) = current.take() {
                        let class_id = u32::from_be_bytes(cur[b"CLAS"][..].try_into().unwrap());
                        bag.class_keys.insert(class_id, ClassKeyData::from_map(cur));
                    }
                    let mut map = HashMap::new();
                    map.insert(tag, data);
                    current = Some(map);
                }
                t if current.is_some()
                    && (t == b"CLAS"
                        || b"WPKY".as_ref() == &t[..]
                        || b"PBKY".as_ref() == &t[..]
                        || b"KTYP".as_ref() == &t[..]
                        || b"WRAP" == &t[..]) =>
                {
                    current.as_mut().unwrap().insert(tag, data);
                }
                _ => {
                    bag.attrs.insert(tag, data);
                }
            }
        }
        // don't forget the last one
        if let Some(cur) = current {
            let class_id = u32::from_be_bytes(cur[b"CLAS"][..].try_into().unwrap());
            bag.class_keys.insert(class_id, ClassKeyData::from_map(cur));
        }
        bag
    }
}

/// Data for a single protection class key entry.
#[derive(Debug, Deserialize, Clone)]
pub struct ClassKeyData {
    /// Alternative WPKY if provided.
    pub wpky: Option<Vec<u8>>,
    /// Alternative WRAP, if provided.
    pub wrap: Option<Vec<u8>>,
    /// Alternative UUID, if provided.
    pub uuid: Option<Vec<u8>>,
}

impl ClassKeyData {
    pub fn from_map(map: HashMap<[u8; 4], Vec<u8>>) -> ClassKeyData {
        // Prefer WPKY, fallback to PBKY for persistent key
        let wpky = map
            .get(b"WPKY")
            .cloned()
            .or_else(|| map.get(b"PBKY").cloned());
        ClassKeyData {
            wpky,
            wrap: map.get(b"WRAP").cloned(),
            uuid: map.get(b"UUID").cloned(),
        }
    }
}

/// In-memory manifest state: raw plist + keys.
#[derive(Debug, Clone)]
pub struct ManifestData {
    /// Parsed `Manifest.plist` data.
    pub manifest: Manifest,
    /// Derived decryption key (32 bytes) if encrypted.
    pub main_decryption_key: Option<Vec<u8>>,
    /// Unwrapped per-class keys after decryption.
    pub unlocked_class_keys: Option<HashMap<u32, ProtectionClassKey>>,
}

/// Decrypted key for a specific protection class.
#[derive(Debug, Clone)]
pub struct ProtectionClassKey {
    /// Numeric class identifier (e.g., 4).
    pub class_id: u32,
    /// Raw decrypted AES key.
    pub key: Vec<u8>,
}

/// Holds information for opening the backup's `Manifest.db`.
#[derive(Debug, Clone)]
pub struct DecryptedManifestDb {
    /// Path to the SQLite database file.
    pub db_path: PathBuf,
    /// Whether `db_path` points to a temporary decrypted file.
    pub is_temporary: bool,
    /// Connection string (usually the file path).
    pub connection_string: String,
    /// Optional hex-encoded SQLCipher key to use when opening.
    pub decryption_key: Option<String>,
}

impl DecryptedManifestDb {
    /// Open a rusqlite `Connection`, applying SQLCipher key if needed.
    pub fn try_get_connection(&self) -> Result<rusqlite::Connection> {
        let conn = rusqlite::Connection::open(&self.db_path).map_err(BackupError::Database)?;
        if let Some(key) = &self.decryption_key {
            // The key for SQLCipher must be provided as a hex string prefixed by "x"
            // or as a raw byte string using `pragma key = '...'` for strings or `pragma key = x'...'` for hex.
            // rusqlite's `key` pragma helper handles this.
            // The simplest way is to use the `key()` method if available (often with `sqlcipher` feature directly on rusqlite)
            // or execute PRAGMA key.
            // For `bundled` (which implies SQLCipher), PRAGMA key is standard.
            conn.pragma_update(None, "key", format!("x'{}'", key))
                .map_err(BackupError::Database)?;

            // Test the key by trying to access data. If the key is wrong, this will likely fail.
            // A simple query like "SELECT count(*) FROM sqlite_master" can verify.
            let mut stmt = conn.prepare("SELECT count(*) FROM sqlite_master")?;
            stmt.query_row([], |_| Ok(()))?;
        }
        Ok(conn)
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct MBFile {
    pub last_modified: u64,
    pub flags: u64,
    pub group_id: i64,
    pub last_status_change: u64,
    pub birth: u64,
    pub size: u64,
    pub mode: u64,
    pub user_id: Option<u64>,
    pub inode_number: u64,
    pub protection_class: u32,
    pub encryption_key: Option<Vec<u8>>,
}

impl MBFile {
    /// Generate an instance from a NSKeyedArchiver blob.
    pub fn from_plist(plist_data: Value) -> Result<MBFile> {
        // parse top-level dictionary
        let dict = plist_data.as_dictionary().ok_or_else(|| {
            BackupError::PlistParseError("MBFile plist is not a dictionary".into())
        })?;
        let root_uid = dict
            .get("$top")
            .and_then(Value::as_dictionary)
            .and_then(|d| d.get("root"))
            .and_then(Value::as_uid)
            .map(|u| u.get() as usize)
            .ok_or_else(|| BackupError::MissingPlistKey("Missing root UID".into()))?;
        let objects = dict
            .get("$objects")
            .and_then(Value::as_array)
            .ok_or_else(|| BackupError::MissingPlistKey("Missing $objects array".into()))?;
        let top_dict = objects
            .get(root_uid)
            .and_then(Value::as_dictionary)
            .ok_or_else(|| BackupError::PlistParseError("Top object is not a dictionary".into()))?;

        // helper functions for extracting values
        let get = |key: &str| {
            top_dict
                .get(key)
                .ok_or_else(|| BackupError::MissingPlistKey(format!("Missing key {}", key)))
        };
        let get_uint = |key: &str| {
            get(key)?.as_unsigned_integer().ok_or_else(|| {
                BackupError::MissingPlistKey(format!("Invalid unsigned integer for {}", key))
            })
        };
        let get_int = |key: &str| {
            get(key)?.as_signed_integer().ok_or_else(|| {
                BackupError::MissingPlistKey(format!("Invalid signed integer for {}", key))
            })
        };

        // optional encryption key
        let encryption_key = if let Some(uid_val) =
            top_dict.get("EncryptionKey").and_then(Value::as_uid)
        {
            let idx = uid_val.get() as usize;
            let data_dict = objects
                .get(idx)
                .and_then(Value::as_dictionary)
                .ok_or_else(|| {
                    BackupError::PlistParseError("EncryptionKey object is not a dictionary".into())
                })?;
            let data = data_dict
                .get("NS.data")
                .and_then(Value::as_data)
                .ok_or_else(|| BackupError::PlistParseError("NS.data missing".into()))?;
            Some(data.to_vec())
        } else {
            None
        };

        Ok(MBFile {
            last_modified: get_uint("LastModified")?,
            flags: get_uint("Flags")?,
            group_id: get_int("GroupID")?,
            last_status_change: get_uint("LastStatusChange")?,
            birth: get_uint("Birth")?,
            size: get_uint("Size")?,
            mode: get_uint("Mode")?,
            user_id: top_dict.get("UserID").and_then(Value::as_unsigned_integer),
            inode_number: get_uint("InodeNumber")?,
            protection_class: get_uint("ProtectionClass")? as u32,
            encryption_key,
        })
    }
}

/// Entry for a single file recorded in `Manifest.db`.
#[derive(Debug, Clone)]
pub struct BackupFileEntry {
    /// Unique file identifier (SHA1 of domain+path).
    pub file_id: String,
    /// Domain of the file (app, library, etc.).
    pub domain: String,
    /// Relative path inside the domain.
    pub relative_path: String,
    /// File flags as stored in the database.
    pub flags: u32,
    /// Protection class ID.
    pub metadata: MBFile,
}
