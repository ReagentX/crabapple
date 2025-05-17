//! Authentication method for encrypted backups.

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
