//! Backup key bags and class key models.

use std::collections::HashMap;

use crate::backup::util::tlv::tlv_blocks;

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
    #[must_use]
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
                        bag.class_keys
                            .insert(class_id, ClassKeyData::from_map(&cur));
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
            bag.class_keys
                .insert(class_id, ClassKeyData::from_map(&cur));
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
    #[must_use]
    pub fn from_map(map: &HashMap<[u8; 4], Vec<u8>>) -> ClassKeyData {
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

/// Stores a decrypted `AES` key for a specific protection class.
#[derive(Debug, Clone)]
pub struct ProtectionClassKey {
    /// Numeric class identifier
    pub class_id: u32,
    /// Raw decrypted `AES` key.
    pub key: Vec<u8>,
}
