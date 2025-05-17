use plist::{Value, dictionary::Dictionary};

use crate::error::{BackupError, Result};

pub fn as_dictionary(plist_data: &Value) -> Result<&Dictionary> {
    plist_data
        .as_dictionary()
        .ok_or_else(|| BackupError::PlistParseError("Top-level plist is not a dictionary".into()))
}

pub fn get_key_as_string(dict: &Dictionary, key: &str) -> Result<String> {
    dict.get(key)
        .ok_or_else(|| BackupError::PlistParseError(format!("Key {key} not found in plist!")))
        .and_then(|v| {
            v.as_string()
                .ok_or_else(|| BackupError::PlistParseError(format!("Key {key} is not a string!")))
        })
        .map(std::string::ToString::to_string)
}

pub fn get_key_as_data(dict: &Dictionary, key: &str) -> Result<Vec<u8>> {
    dict.get(key)
        .ok_or_else(|| BackupError::PlistParseError(format!("Key {key} not found in plist!")))
        .and_then(|v| {
            v.as_data()
                .ok_or_else(|| BackupError::PlistParseError(format!("Key {key} is not data!")))
        })
        .map(<[u8]>::to_vec)
}

pub fn get_key_as_boolean(dict: &Dictionary, key: &str) -> Result<bool> {
    dict.get(key)
        .ok_or_else(|| BackupError::PlistParseError(format!("Key {key} not found in plist!")))
        .and_then(|v| {
            v.as_boolean()
                .ok_or_else(|| BackupError::PlistParseError(format!("Key {key} is not boolean!")))
        })
        .map(|b| b.to_owned())
}

pub fn get_key_as_uint(dict: &Dictionary, key: &str) -> Result<u64> {
    dict.get(key)
        .ok_or_else(|| BackupError::PlistParseError(format!("Key {key} not found in plist!")))
        .and_then(|v| {
            v.as_unsigned_integer()
                .ok_or_else(|| BackupError::PlistParseError(format!("Key {key} is not uint!")))
        })
        .map(|u| u.to_owned())
}

pub fn get_key_as_int(dict: &Dictionary, key: &str) -> Result<i64> {
    dict.get(key)
        .ok_or_else(|| BackupError::PlistParseError(format!("Key {key} not found in plist!")))
        .and_then(|v| {
            v.as_signed_integer()
                .ok_or_else(|| BackupError::PlistParseError(format!("Key {key} is not int!")))
        })
        .map(|i| i.to_owned())
}
