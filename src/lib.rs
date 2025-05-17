#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

/// Main library for interacting with iOS backups, providing types and methods for decryption and metadata access.
pub mod backup;
pub mod error;

/// Main library for interacting with iOS backups, providing types and methods for decryption and metadata access.
pub use backup::Backup;

/// File entry representation in the backup database, including metadata and encryption info.
pub use crate::backup::models::file::BackupFileEntry;

/// Authentication options for encrypted backups: either a password or a pre-derived key.
pub use backup::models::auth::Authentication;

/// Retrieve basic device metadata from a given backup folder UDID.
pub use backup::device::get_device_basic_info;

/// The error type for all operations in the `crabapple` crate.
pub use error::{BackupError, Result};
