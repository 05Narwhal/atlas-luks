// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! LUKS1 and LUKS2 volumes: reading the header, finding the volume key from a
//! password and decrypting the payload as it is read.
//!
//! [`luks`] parses the LUKS1 and LUKS2 headers and unlocks a keyslot with a
//! password; [`source::Decrypted`] is the [`BlockSource`](atlas_fs_core::io::block::BlockSource)
//! that decrypts the payload sector by sector (AES-XTS and AES-CBC); [`xts`]
//! is AES-XTS written over the `aes` block cipher; [`kdf`] holds PBKDF2,
//! Argon2 and the anti-forensic merge. Reading only: nothing here writes.
//!
//! Secrets (the password, derived keys, keyslot material, the volume key) live
//! in [`zeroize::Zeroizing`] buffers and are wiped when dropped. Nothing formats
//! or logs one, and no key-holding type derives `Debug`.
//!
//! ```no_run
//! use std::path::Path;
//! use std::sync::Arc;
//!
//! use atlas_fs_core::io::block::BlockSource;
//! use atlas_fs_core::io::file::FileSource;
//!
//! # fn main() -> Result<(), atlas_fs_core::error::Error> {
//! let source: Arc<dyn BlockSource> = Arc::new(FileSource::open(Path::new("volume.img"))?);
//! let volume = atlas_luks::luks::open(source)?;
//! let payload = volume.unlock_source("password")?;
//! println!("{} bytes of decrypted payload", payload.len());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
// On-disk bytes are hostile. These lints make the usual ways of trusting
// them (unchecked indexing, arithmetic and casts, panicking shortcuts) fail
// the clippy gate. Unit tests and the test fixtures are exempt.
#![warn(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::unwrap_used
)]
#![cfg_attr(
    any(test, feature = "test-util"),
    allow(
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )
)]

use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location};

pub mod kdf;
pub mod luks;
pub mod source;
pub mod xts;

/// Test images, built from the packed `cryptsetup` fixtures (`test-util` only).
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub mod test_image;
#[cfg(test)]
mod tests;

/// A damaged-header error for `structure`, with no location.
pub(crate) fn corrupt(structure: &'static str, kind: CorruptKind) -> Error {
    Error::Corrupt(Corruption::new(structure, Location::Unspecified, kind))
}

/// A field that is missing or holds a value the format does not allow.
pub(crate) fn bad_field(structure: &'static str, field: &'static str, value: u64) -> Error {
    corrupt(structure, CorruptKind::InvalidValue { field, value })
}

/// A field that points or counts past `limit`.
pub(crate) fn out_of_range(
    structure: &'static str,
    field: &'static str,
    value: u64,
    limit_name: &'static str,
    limit: u64,
) -> Error {
    corrupt(
        structure,
        CorruptKind::OutOfRange {
            field,
            value,
            limit_name,
            limit,
        },
    )
}

/// `text` shortened and stripped of control characters, for an error message
/// that names a cipher or a hash found on disk.
pub(crate) fn clip(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(40)
        .collect::<String>()
}
