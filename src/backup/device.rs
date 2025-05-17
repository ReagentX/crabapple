//! Device helper functions for listing device backups and retrieving basic device information.

use crate::backup::types::{ManifestLockdownInfo, Manifest};
use crate::error::{BackupError, Result};
use std::path::Path;

/// Get basic device metadata for a specific UDID.
///
/// Reads and parses `Manifest.plist` from the provided device backup path to return lockdown info.
///
/// # Arguments
///
/// * `device_backup_path` - Path to a specific device UDID backup folder.
///
/// # Errors
/// Returns `BackupError::ManifestPlistNotFound` if `Manifest.plist` is missing,
/// or `BackupError::Plist` if parsing fails.
pub fn get_device_basic_info(device_backup_path: &Path) -> Result<ManifestLockdownInfo> {
    let plist_path = device_backup_path.join("Manifest.plist");
    if !plist_path.exists() {
        return Err(BackupError::ManifestPlistNotFound(
            plist_path.display().to_string(),
        ));
    }
    let info = Manifest::load(&plist_path)?;
    Ok(info.lockdown)
}
