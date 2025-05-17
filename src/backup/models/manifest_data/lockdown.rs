//! Device metadata from the backup's `Manifest.plist`.

use plist::Value;

use crate::{
    backup::util::plist::get_key_as_string,
    error::{BackupError, Result},
};

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
    pub(crate) fn from_plist(plist_data: Value) -> Result<ManifestLockdownInfo> {
        let dict = plist_data.as_dictionary().ok_or_else(|| {
            BackupError::PlistParseError("ManifestLockdownInfo plist is not a dictionary".into())
        })?;

        Ok(ManifestLockdownInfo {
            build_version: get_key_as_string(dict, "BuildVersion")?,
            device_name: get_key_as_string(dict, "DeviceName")?,
            product_type: get_key_as_string(dict, "ProductType")?,
            product_version: get_key_as_string(dict, "ProductVersion")?,
            serial_number: get_key_as_string(dict, "SerialNumber")?,
            unique_device_id: get_key_as_string(dict, "UniqueDeviceID")?,
        })
    }
}
