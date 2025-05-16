# crabapple

Crabapple is a Rust library for reading, inspecting, and extracting data from encrypted iOS backups created by Finder, Apple Devices, or iTunes.

# ⚠️ Warning ⚠️

This library is currently in an alpha state and should not be used in production code.

## Features

- Load and parse the backup's `Manifest.plist` to obtain metadata, device info, and encryption parameters
- Derive encryption keys using `PBKDF2-HMAC-SHA1` and unwrap protection class keys (`AES-KW`)
- Decrypt and query the `AES-256` encrypted `Manifest.db` to represent backup file metadata
- Retrieve and decrypt individual files by protection class
- Cross-platform support for macOS, Windows, and Linux

## Installation

This library is available on [`crates.io`](https://crates.io/crates/crabapple)

## Documentation

API documentation is available at [`docs.rs`](https://docs.rs/crabapple).

## Quick Start

```rust ,no_run
use crabapple::{Backup, Authentication};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize a backup session for a device UDID with a password
    let udid_folder = "/Users/you/Library/Application Support/MobileSync/Backup/DEVICE_UDID";
    let auth = Authentication::Password("your_password".into());
    let backup = Backup::new(udid_folder, auth)?;

    // List all files in the backup
    let entries = backup.get_backup_files_list()?;
    for entry in entries {
        println!("{} - {}/{}", entry.file_id, entry.domain, entry.relative_path);
    }

    // Decrypt and read a specific file
    let data = backup.get_file_decrypted_copy("Manifest.db")?;
    println!("Read {} bytes", data.len());

    Ok(())
}
```

## Crabapple Tree

![My Crabapple Tree](/resources/crabapple.png)
