// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! [`Decrypted`]: a read-only `BlockSource` that decrypts an encrypted payload
//! as it is read, and the sector ciphers it uses.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::clip;
use super::xts::{AesKey, Xts, tweak_of};
use atlas_fs_core::error::{Error, Result};
use atlas_fs_core::io::block::{BlockSource, check_range};

/// The most bytes read and decrypted in one call to the inner source.
const MAX_RUN: u64 = 1 << 20;

/// How a sector's initialisation vector comes from its number.
#[derive(Clone, Copy)]
enum Iv {
    /// 64-bit little-endian sector number (`plain64`).
    Plain64,
    /// 32-bit little-endian sector number (`plain`).
    Plain32,
}

/// A cipher for whole sectors: what dm-crypt calls `cipher-chainmode-iv`.
///
/// Supported: AES in XTS mode with `plain` or `plain64` IVs, and AES in CBC
/// mode with `plain`, `plain64` or `essiv:sha256` IVs. The key is wiped when
/// the cipher drops.
pub struct SectorCipher(Mode);

/// The modes behind [`SectorCipher`].
enum Mode {
    /// AES-XTS; the tweak is the sector number.
    Xts(Xts, Iv),
    /// AES-CBC with the IV from the number alone.
    CbcPlain(AesKey, Iv),
    /// AES-CBC with the IV encrypted under a hash of the key.
    CbcEssiv {
        /// Decrypts the data.
        key: AesKey,
        /// Encrypts the sector number into the IV.
        iv: AesKey,
    },
}

impl SectorCipher {
    /// The cipher `spec` names (`aes-xts-plain64`, `aes-cbc-essiv:sha256`,
    /// ...) keyed with `key`. Another cipher, mode, IV or key size is
    /// `Error::Unsupported` naming it.
    pub fn parse(spec: &str, key: &[u8]) -> Result<Self> {
        let unsupported = || Error::unsupported(format!("cipher {}", clip(spec)));
        let (cipher, rest) = spec.split_once('-').ok_or_else(unsupported)?;
        let (mode, iv) = rest.split_once('-').ok_or_else(unsupported)?;
        if cipher != "aes" {
            return Err(unsupported());
        }
        let iv_kind = match iv {
            "plain64" => Some(Iv::Plain64),
            "plain" => Some(Iv::Plain32),
            _ => None,
        };
        match (mode, iv_kind, iv) {
            ("xts", Some(kind), _) => Ok(Self(Mode::Xts(
                Xts::new(key).ok_or_else(unsupported)?,
                kind,
            ))),
            ("cbc", Some(kind), _) => Ok(Self(Mode::CbcPlain(
                AesKey::new(key).ok_or_else(unsupported)?,
                kind,
            ))),
            ("cbc", None, "essiv:sha256") => {
                let data = AesKey::new(key).ok_or_else(unsupported)?;
                let mut salt = Zeroizing::new([0u8; 32]);
                salt.copy_from_slice(&Sha256::digest(key));
                let iv = AesKey::new(&*salt).ok_or_else(unsupported)?;
                Ok(Self(Mode::CbcEssiv { key: data, iv }))
            }
            _ => Err(unsupported()),
        }
    }

    /// AES-CBC whose IV is the IV number (BitLocker passes the sector's byte
    /// offset) encrypted with the data key itself: dm-crypt's `aes-cbc-eboiv`.
    /// `key` is 16 or 32 bytes.
    pub fn cbc_eboiv(key: &[u8]) -> Result<Self> {
        let unsupported = || Error::unsupported("AES-CBC key size");
        Ok(Self(Mode::CbcEssiv {
            key: AesKey::new(key).ok_or_else(unsupported)?,
            iv: AesKey::new(key).ok_or_else(unsupported)?,
        }))
    }

    /// Decrypts `data` in place as the sector with IV number `number`. `data`
    /// is a whole number of 16-byte blocks.
    pub fn decrypt_sector(&self, number: u64, data: &mut [u8]) {
        match &self.0 {
            Mode::Xts(xts, iv) => xts.decrypt_sector(iv.apply(number), data),
            Mode::CbcPlain(key, iv) => {
                cbc_decrypt(key, tweak_of(iv.apply(number)), data);
            }
            Mode::CbcEssiv { key, iv } => {
                let mut block = tweak_of(number);
                iv.encrypt(&mut block);
                cbc_decrypt(key, block, data);
            }
        }
    }

    /// Encrypts a sector, for building test data.
    #[cfg(test)]
    pub fn encrypt_sector(&self, number: u64, data: &mut [u8]) {
        match &self.0 {
            Mode::Xts(xts, iv) => xts.encrypt_with_tweak(tweak_of(iv.apply(number)), data),
            Mode::CbcPlain(key, iv) => cbc_encrypt(key, tweak_of(iv.apply(number)), data),
            Mode::CbcEssiv { key, iv } => {
                let mut block = tweak_of(number);
                iv.encrypt(&mut block);
                cbc_encrypt(key, block, data);
            }
        }
    }
}

impl Iv {
    fn apply(self, number: u64) -> u64 {
        match self {
            Self::Plain64 => number,
            Self::Plain32 => number & 0xFFFF_FFFF,
        }
    }
}

fn cbc_decrypt(key: &AesKey, iv: [u8; 16], data: &mut [u8]) {
    let mut previous = iv;
    for block in data.as_chunks_mut::<16>().0.iter_mut() {
        let mut cipher_block = [0u8; 16];
        cipher_block.copy_from_slice(block);
        key.decrypt(block);
        for (b, p) in block.iter_mut().zip(&previous) {
            *b ^= *p;
        }
        previous = cipher_block;
    }
}

#[cfg(test)]
fn cbc_encrypt(key: &AesKey, iv: [u8; 16], data: &mut [u8]) {
    let mut previous = iv;
    for block in data.as_chunks_mut::<16>().0.iter_mut() {
        for (b, p) in block.iter_mut().zip(&previous) {
            *b ^= *p;
        }
        key.encrypt(block);
        previous.copy_from_slice(block);
    }
}

/// An encrypted payload, read as plaintext.
///
/// Reads of any offset and length decrypt the whole sectors they touch. The
/// source is read-only. The key lives inside the cipher and is wiped when the
/// source is dropped.
pub struct Decrypted {
    inner: Arc<dyn BlockSource>,
    cipher: SectorCipher,
    /// Byte offset of the payload in `inner`.
    start: u64,
    /// Payload size, a whole number of sectors.
    len: u64,
    /// Encryption sector size: 512, 1024, 2048 or 4096.
    sector_size: u32,
    /// Added to the IV number of every sector.
    iv_offset: u64,
    /// How much the IV number grows from one sector to the next.
    iv_step: u64,
}

impl Decrypted {
    /// The `len` bytes of `inner` from `start` as plaintext.
    ///
    /// `sector_size` is the encryption sector (512 to 4096, a power of two);
    /// `len` is a multiple of it; the IV number of sector `i` is
    /// `iv_offset + i * iv_step`. Fails with `Error::OutOfBounds` when the
    /// range does not lie inside `inner` and `Error::Unsupported` for a sector
    /// size the format does not allow.
    pub fn new(
        inner: Arc<dyn BlockSource>,
        cipher: SectorCipher,
        start: u64,
        len: u64,
        sector_size: u32,
        iv_offset: u64,
        iv_step: u64,
    ) -> Result<Self> {
        if !matches!(sector_size, 512 | 1024 | 2048 | 4096) {
            return Err(Error::unsupported("encryption sector size"));
        }
        let size = inner.len();
        match start.checked_add(len) {
            Some(end) if end <= size && len.is_multiple_of(u64::from(sector_size)) => Ok(Self {
                inner,
                cipher,
                start,
                len,
                sector_size,
                iv_offset,
                iv_step,
            }),
            _ => Err(Error::OutOfBounds {
                offset: start,
                len,
                size,
            }),
        }
    }

    /// The IV number of sector `index`.
    fn iv_number(&self, index: u64) -> u64 {
        self.iv_offset
            .wrapping_add(index.wrapping_mul(self.iv_step))
    }

    /// Decrypts `data`, a run of whole sectors starting at sector `first`.
    fn decrypt_run(&self, first: u64, data: &mut [u8]) {
        let size = usize::try_from(self.sector_size).unwrap_or(512);
        for (n, sector) in data.chunks_exact_mut(size).enumerate() {
            let index = first.wrapping_add(n as u64);
            self.cipher.decrypt_sector(self.iv_number(index), sector);
        }
    }
}

fn out_of_bounds(offset: u64, len: usize, size: u64) -> Error {
    Error::OutOfBounds {
        offset,
        len: u64::try_from(len).unwrap_or(u64::MAX),
        size,
    }
}

impl BlockSource for Decrypted {
    fn len(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.len)?;
        let total = buf.len();
        let oob = || out_of_bounds(offset, total, self.len);
        let sector = u64::from(self.sector_size);
        let mut bounce: Vec<u8> = Vec::new();
        let mut done = 0usize;
        while done < buf.len() {
            let remaining = buf.len().checked_sub(done).ok_or_else(oob)?;
            let at = offset
                .checked_add(u64::try_from(done).map_err(|_| oob())?)
                .ok_or_else(oob)?;
            let index = at.checked_div(sector).ok_or_else(oob)?;
            let within = at.checked_rem(sector).ok_or_else(oob)?;
            let disk = index
                .checked_mul(sector)
                .and_then(|n| n.checked_add(self.start))
                .ok_or_else(oob)?;
            let whole = u64::try_from(remaining)
                .map_err(|_| oob())?
                .checked_div(sector)
                .ok_or_else(oob)?;
            if within == 0 && whole > 0 {
                // Aligned: read straight into the caller's buffer and decrypt there.
                let run = whole
                    .min(MAX_RUN.checked_div(sector).unwrap_or(1))
                    .max(1)
                    .checked_mul(sector)
                    .ok_or_else(oob)?;
                let run = usize::try_from(run).map_err(|_| oob())?;
                let end = done.checked_add(run).ok_or_else(oob)?;
                let target = buf.get_mut(done..end).ok_or_else(oob)?;
                self.inner.read_at(disk, target)?;
                self.decrypt_run(index, target);
                done = end;
            } else {
                // A partial sector at the start or the end: decrypt it in a side buffer.
                let size = usize::try_from(self.sector_size).map_err(|_| oob())?;
                bounce.resize(size, 0);
                self.inner.read_at(disk, &mut bounce)?;
                self.decrypt_run(index, &mut bounce);
                let skip = usize::try_from(within).map_err(|_| oob())?;
                let avail = size.checked_sub(skip).ok_or_else(oob)?;
                let take = avail.min(remaining);
                let end = done.checked_add(take).ok_or_else(oob)?;
                let from = skip.checked_add(take).ok_or_else(oob)?;
                let src = bounce.get(skip..from).ok_or_else(oob)?;
                buf.get_mut(done..end).ok_or_else(oob)?.copy_from_slice(src);
                done = end;
            }
        }
        Ok(())
    }
}
