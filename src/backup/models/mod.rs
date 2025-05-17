//! Model definitions for iOS backup metadata structures, authentication, and file entries.

pub mod auth;
pub mod file;
pub mod keyring;
pub mod manifest_data;

#[cfg(test)]
mod tests_types {
    use plist::Value;
    use std::collections::HashMap;

    use crate::backup::models::{
        keyring::{BackupKeyBag, ClassKeyData},
        manifest_data::lockdown::ManifestLockdownInfo,
    };

    #[test]
    fn test_manifest_lockdown_info_from_plist() {
        // Build a plist dictionary
        let mut dict = plist::Dictionary::new();
        dict.insert("BuildVersion".into(), Value::String("1.2.3".into()));
        dict.insert("DeviceName".into(), Value::String("TestDevice".into()));
        dict.insert("ProductType".into(), Value::String("TestType".into()));
        dict.insert("ProductVersion".into(), Value::String("14.0".into()));
        dict.insert("SerialNumber".into(), Value::String("SN123".into()));
        dict.insert("UniqueDeviceID".into(), Value::String("UDID456".into()));
        let value = Value::Dictionary(dict.clone());
        let info = ManifestLockdownInfo::from_plist(value).unwrap();
        assert_eq!(info.build_version, "1.2.3");
        assert_eq!(info.device_name, "TestDevice");
        assert_eq!(info.product_type, "TestType");
        assert_eq!(info.product_version, "14.0");
        assert_eq!(info.serial_number, "SN123");
        assert_eq!(info.unique_device_id, "UDID456");
    }

    #[test]
    fn test_backup_key_bag_from_bytes_basic() {
        // Construct a simple TLV blob: TYPE=1, DPSL=b"aa", DPIC=2, SALT=b"bb", ITER=3
        let mut blob = Vec::new();
        // TYPE
        blob.extend(b"TYPE");
        blob.extend(&4u32.to_be_bytes());
        blob.extend(&1u32.to_be_bytes());
        // DPSL
        blob.extend(b"DPSL");
        blob.extend(&2u32.to_be_bytes());
        blob.extend(b"aa");
        // DPIC
        blob.extend(b"DPIC");
        blob.extend(&4u32.to_be_bytes());
        blob.extend(&2u32.to_be_bytes());
        // SALT
        blob.extend(b"SALT");
        blob.extend(&2u32.to_be_bytes());
        blob.extend(b"bb");
        // ITER
        blob.extend(b"ITER");
        blob.extend(&4u32.to_be_bytes());
        blob.extend(&3u32.to_be_bytes());
        let bag = BackupKeyBag::from_bytes(&blob);

        assert_eq!(bag.bag_type, 1);
        assert_eq!(bag.dpsl, b"aa");
        assert_eq!(bag.dpic, 2);
        assert_eq!(bag.salt, b"bb");
        assert_eq!(bag.iter, 3);
        // No class keys parsed
        assert!(bag.class_keys.is_empty());
    }

    #[test]
    fn test_class_key_data_prefer_wpky() {
        let mut map: HashMap<[u8; 4], Vec<u8>> = HashMap::new();
        map.insert(*b"PBKY", b"pb".to_vec());
        map.insert(*b"WPKY", b"wp".to_vec());
        map.insert(*b"WRAP", b"wr".to_vec());
        map.insert(*b"UUID", b"id".to_vec());
        let ck = ClassKeyData::from_map(map);
        assert_eq!(ck.wpky.unwrap(), b"wp".to_vec());
        assert_eq!(ck.wrap.unwrap(), b"wr".to_vec());
        assert_eq!(ck.uuid.unwrap(), b"id".to_vec());
    }
}
