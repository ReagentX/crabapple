//! File metadata and cryptographic information for backup entries.
use std::{ops::Deref, path::PathBuf};

use plist::Value;

use crate::{
    backup::util::plist::{as_dictionary, get_key_as_data, get_key_as_int, get_key_as_uint},
    error::{BackupError, Result},
};

#[derive(Debug, Clone)]
pub struct FileKeyPair {
    pub protection_class_id: u32,
    pub file_key: WrappedKey,
}

impl FileKeyPair {
    /// Deserialize the protection class identifier and the key blob for a file.
    ///
    /// The first 4 bytes of a key are interpreted as a little-endian
    /// `u32` protection class identifier. The remainder is treated as an AES-key-wrapped
    /// file key (`RFC 3394`).
    ///
    /// # Examples
    ///
    /// ```
    /// use crabapple::backup::models::file::FileKeyPair;
    ///
    /// let bytes = &[1, 0, 0, 0, 0xAA, 0xBB, 0xCC];
    /// let fk = FileKeyPair::new(bytes);
    ///
    /// assert_eq!(fk.protection_class_id, 1);
    /// ```
    pub fn new(key: &[u8]) -> Self {
        let parts = key.split_at(4);
        FileKeyPair {
            protection_class_id: u32::from_le_bytes(parts.0.try_into().unwrap()),
            file_key: WrappedKey(parts.1.to_vec()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Wrapper type for an `AES`-wrapped file key used in backup file encryption.
///
/// This newtype wraps a `Vec<u8>` representing a file encryption key that has been
/// wrapped using the AES key wrap algorithm (`RFC 3394`).
pub struct WrappedKey(Vec<u8>);

impl AsRef<[u8]> for WrappedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for WrappedKey {
    fn from(v: Vec<u8>) -> WrappedKey {
        WrappedKey(v)
    }
}

impl Deref for WrappedKey {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.0
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
    pub encryption_key: Option<FileKeyPair>,
}

impl MBFile {
    /// Deserialize an `NSKeyedArchiver` blob into an `MBFile`, extracting file metadata and encryption info.
    ///
    /// # Arguments
    /// * `plist_data` - A plist `Value` representing the `MBFile` object.
    ///
    /// # Errors
    /// Returns [`BackupError::MissingPlistKey`] or [`BackupError::PlistParseError`] on parse failure.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use plist::Value;
    /// use crabapple::backup::models::file::MBFile;
    ///
    /// let plist: Value = /* load your plist here */ unimplemented!();
    /// let mb = MBFile::from_plist(&plist).unwrap();
    /// println!("Size: {} bytes", mb.size);
    /// ```
    pub fn from_plist(plist_data: &Value) -> Result<MBFile> {
        // parse top-level dictionary
        let dict = as_dictionary(plist_data)?;

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

        let top_dict = as_dictionary(objects.get(root_uid).ok_or_else(|| {
            BackupError::PlistParseError("Could not resolve MBFile Dictionary".into())
        })?)?;

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

            let data = get_key_as_data(data_dict, "NS.data")?;
            Some(FileKeyPair::new(&data))
        } else {
            None
        };

        Ok(MBFile {
            last_modified: get_key_as_uint(top_dict, "LastModified")?,
            flags: get_key_as_uint(top_dict, "Flags")?,
            group_id: get_key_as_int(top_dict, "GroupID")?,
            last_status_change: get_key_as_uint(top_dict, "LastStatusChange")?,
            birth: get_key_as_uint(top_dict, "Birth")?,
            size: get_key_as_uint(top_dict, "Size")?,
            mode: get_key_as_uint(top_dict, "Mode")?,
            user_id: top_dict.get("UserID").and_then(Value::as_unsigned_integer),
            inode_number: get_key_as_uint(top_dict, "InodeNumber")?,
            protection_class: get_key_as_uint(top_dict, "ProtectionClass")? as u32,
            encryption_key,
        })
    }
}

/// Entry for a single file recorded in `Manifest.db`, including its ID, path, flags, and metadata.
#[derive(Debug, Clone)]
pub struct BackupFileEntry {
    /// Unique file identifier (`SHA1` of domain+path).
    pub file_id: String,
    /// Domain of the file (app, library, etc.).
    pub domain: String,
    /// Relative path inside the domain.
    pub relative_path: String,
    /// File flags as stored in the database.
    pub flags: u32,
    /// Metadata and cryptographic information for the file entry.
    pub metadata: MBFile,
}

impl BackupFileEntry {
    #[must_use]
    pub fn source(&self) -> PathBuf {
        PathBuf::from(&self.file_id[0..2]).join(&self.file_id)
    }
}
