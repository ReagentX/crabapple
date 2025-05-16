//! Type definitions for iOS backup metadata structures, authentication, and file entries.

use plist::Value;
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};

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
    /// Returns [`BackupError::General`] if the file cannot be opened or parsed.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();
        let file = File::open(path_ref)
            .map_err(|_| BackupError::ManifestPlistNotFound(path_ref.display().to_string()))?;
        let plist = Value::from_reader(file)?;
        let dict = plist.as_dictionary().ok_or_else(|| {
            BackupError::PlistParseError("Top-level plist is not a dictionary".into())
        })?;
        let is_encrypted = dict
            .get("IsEncrypted")
            .and_then(Value::as_boolean)
            .unwrap_or(false);
        let backup_key_bag = if is_encrypted {
            let data = dict
                .get("BackupKeyBag")
                .ok_or_else(|| BackupError::MissingPlistKey("BackupKeyBag".into()))?
                .as_data()
                .ok_or_else(|| BackupError::PlistParseError("BackupKeyBag is not data".into()))?;
            Some(BackupKeyBag::from_bytes(data))
        } else {
            None
        };
        let manifest_key = if is_encrypted {
            let data = dict
                .get("ManifestKey")
                .ok_or_else(|| BackupError::MissingPlistKey("ManifestKey".into()))?
                .as_data()
                .ok_or_else(|| BackupError::PlistParseError("ManifestKey is not data".into()))?;
            Some(data.to_vec())
        } else {
            None
        };
        let lockdown_val = dict
            .get("Lockdown")
            .ok_or_else(|| BackupError::MissingPlistKey("Lockdown".into()))?;
        let lockdown = ManifestLockdownInfo::from_plist(lockdown_val.clone())?;
        Ok(Manifest {
            backup_key_bag,
            is_encrypted,
            lockdown,
            manifest_key,
        })
    }
}

/// Device metadata from the backup's `Manifest.plist`.
#[derive(Debug, Clone)]
pub struct ManifestLockdownInfo {
    /// iOS build version (e.g., `"18E199"`).
    pub build_version: String,
    /// Human-readable device name.
    pub device_name: String,
    /// Device product type (e.g., `"iPhone9,4"`).
    pub product_type: String,
    /// iOS version (e.g., `"15.5"`).
    pub product_version: String,
    /// Device serial number.
    pub serial_number: String,
    /// Unique device identifier (`UDID`).
    pub unique_device_id: String,
}

impl ManifestLockdownInfo {
    /// Parse from plist
    fn from_plist(plist_data: Value) -> Result<ManifestLockdownInfo> {
        let dict = plist_data.as_dictionary().ok_or_else(|| {
            BackupError::PlistParseError("ManifestLockdownInfo plist is not a dictionary".into())
        })?;

        Ok(ManifestLockdownInfo {
            build_version: dict
                .get("BuildVersion")
                .unwrap()
                .as_string()
                .unwrap()
                .to_string(),
            device_name: dict
                .get("DeviceName")
                .unwrap()
                .as_string()
                .unwrap()
                .to_string(),
            product_type: dict
                .get("ProductType")
                .unwrap()
                .as_string()
                .unwrap()
                .to_string(),
            product_version: dict
                .get("ProductVersion")
                .unwrap()
                .as_string()
                .unwrap()
                .to_string(),
            serial_number: dict
                .get("SerialNumber")
                .unwrap()
                .as_string()
                .unwrap()
                .to_string(),
            unique_device_id: dict
                .get("UniqueDeviceID")
                .unwrap()
                .as_string()
                .unwrap()
                .to_string(),
        })
    }
}

/// Represents the key bag from `Manifest.plist` containing encryption parameters and wrapped class keys.
#[derive(Debug, Clone)]
pub struct BackupKeyBag {
    /// Bag type identifier (backup key bag version).
    pub bag_type: u32,
    /// Unique identifier for the backup key bag (`UUID` TLV field).
    pub uuid: Vec<u8>,
    /// Optional wrap key blob for certain classes (TLV 'WRAP').
    pub wrap: Vec<u8>,
    /// DPSL parameter for initial `PBKDF2` derivation (TLV 'DPSL').
    pub dpsl: Vec<u8>,
    /// DPIC iteration count for initial `PBKDF2` derivation (TLV 'DPIC').
    pub dpic: u32,
    /// Salt for second `PBKDF2` derivation (TLV 'SALT').
    pub salt: Vec<u8>,
    /// Iteration count for second `PBKDF2` derivation (TLV 'ITER').
    pub iter: u32,
    /// Other TLV attributes not explicitly parsed (raw tag-to-blob map).
    pub attrs: HashMap<[u8; 4], Vec<u8>>,
    /// Map of protection class IDs to their wrapped key data.
    pub class_keys: HashMap<u32, ClassKeyData>,
}

impl BackupKeyBag {
    /// Parse a raw backup key bag blob into a [`BackupKeyBag`], extracting TLV fields.
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

/// Contains wrapped key variants and metadata for a single protection class entry.
#[derive(Debug, Clone)]
pub struct ClassKeyData {
    /// Alternative WPKY if provided.
    pub wpky: Option<Vec<u8>>,
    /// Alternative WRAP, if provided.
    pub wrap: Option<Vec<u8>>,
    /// Alternative UUID, if provided.
    pub uuid: Option<Vec<u8>>,
}

impl ClassKeyData {
    /// Build a [`ClassKeyData`] from a TLV attribute map.
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

/// Holds in-memory parsed manifest (`Manifest.plist`) and associated decryption key and unwrapped class keys.
#[derive(Debug, Clone)]
pub struct ManifestData {
    /// Parsed `Manifest.plist` data.
    pub manifest: Manifest,
    /// Derived decryption key (`32` bytes) if encrypted.
    pub main_decryption_key: Option<Vec<u8>>,
    /// Unwrapped per-class keys after decryption.
    pub unlocked_class_keys: Option<HashMap<u32, ProtectionClassKey>>,
}

/// Stores a decrypted `AES` key for a specific protection class.
#[derive(Debug, Clone)]
pub struct ProtectionClassKey {
    /// Numeric class identifier
    pub class_id: u32,
    /// Raw decrypted `AES` key.
    pub key: Vec<u8>,
}

/// Holds information for opening a backup's `Manifest.db`, including file path and optional SQLCipher key.
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
    /// Open a `SQLite` connection to the manifest database, applying SQLCipher key if needed.
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

/// Metadata and cryptographic information for a single backup file entry.
#[derive(Debug, Clone)]
pub struct MBFile {
    /// Last modification timestamp (seconds since `UNIX` epoch).
    pub last_modified: u64,
    /// File flags as stored in the backup database.
    pub flags: u64,
    /// Group ID (owner) of the file.
    pub group_id: i64,
    /// Last status change timestamp (seconds since `UNIX` epoch).
    pub last_status_change: u64,
    /// Creation (birth) timestamp (seconds since `UNIX` epoch).
    pub birth: u64,
    /// File size in bytes.
    pub size: u64,
    /// File mode/permission bits.
    pub mode: u64,
    /// Optional user ID of the file owner.
    pub user_id: Option<u64>,
    /// Inode number recorded in backup.
    pub inode_number: u64,
    /// Protection class identifier for the file.
    pub protection_class: u32,
    /// Optional wrapped encryption key blob (includes class in first 4 bytes).
    pub encryption_key: Option<Vec<u8>>,
}

impl MBFile {
    /// Deserialize an `NSKeyedArchiver` blob into an `MBFile`, extracting file metadata and encryption info.
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

/// Entry for a single file recorded in `Manifest.db`, including its ID, path, flags, and metadata.
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
