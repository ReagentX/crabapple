//! File metadata and cryptographic information for backup entries.
use std::path::PathBuf;

use plist::Value;

use crate::{
    backup::util::plist::{as_dictionary, get_key_as_data, get_key_as_int, get_key_as_uint},
    error::{BackupError, Result},
};

#[derive(Debug, Clone)]
// The first 4 bytes of a key are interpreted as a little-endian
// `u32` protection class identifier. The remainder is treated as an AES-key-wrapped
// file key (`RFC 3394`).
pub struct FileKey {
    key: Vec<u8>,
}

impl FileKey {
    pub fn new(key: Vec<u8>) -> Self {
        FileKey { key }
    }

    /// Get the protection class identifier and the key blob.
    ///
    /// # Returns
    /// A tuple containing the 4-byte class identifier and the remaining key bytes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crabapple::backup::models::file::FileKey;
    ///
    /// let bytes = &[0,0,0,1, 0xAA,0xBB,0xCC];
    /// let fk = FileKey::new(bytes.to_vec());
    /// let (class_id_bytes, key_blob) = fk.get_class_key();
    ///
    /// assert_eq!(class_id_bytes, &[0,0,0,1]);
    /// assert_eq!(key_blob, &[0xAA,0xBB,0xCC]);
    /// ```
    #[must_use]
    pub fn get_class_key(&self) -> (&[u8], &[u8]) {
        self.key.split_at(4)
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
    pub encryption_key: Option<FileKey>,
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
    /// let mb = MBFile::from_plist(plist).unwrap();
    /// println!("Size: {} bytes", mb.size);
    /// ```
    pub fn from_plist(plist_data: Value) -> Result<MBFile> {
        // parse top-level dictionary
        let dict = as_dictionary(&plist_data)?;

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
            Some(FileKey::new(data.clone()))
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
    pub fn source(&self) -> PathBuf {
        PathBuf::from(&self.file_id[0..2]).join(&self.file_id)
    }
}
