#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod backup;
pub mod error;

/// Main interface for accessing an iOS backup.
pub use backup::Backup;

/// Represents a file entry in the backup database.
pub use crate::backup::types::BackupFileEntry;

/// Authentication options for encrypted backups.
pub use backup::types::BackupAuth;

/// Retrieve basic device info from a device backup folder.
pub use backup::device::get_device_basic_info;

/// Error type for all library operations.
pub use error::{BackupError, Result};
