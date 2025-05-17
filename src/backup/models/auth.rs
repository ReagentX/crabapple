//! Authentication method for encrypted backups.

/// Authentication method for encrypted backups.
///
/// Use a plaintext password or provide a pre-derived encryption key (hex-encoded).
///
/// # Examples
///
/// ```no_run
/// use crabapple::Authentication;
///
/// let auth1 = Authentication::Password("password123".to_string());
/// let auth2 = Authentication::DerivedKey("abcdef012345...".to_string());
/// ```
#[derive(Debug, Clone)]
pub enum Authentication {
    /// Cleartext password provided by the user.
    Password(String),
    /// Pre-derived key (hex-encoded) to decrypt backup.
    DerivedKey(String),
}
