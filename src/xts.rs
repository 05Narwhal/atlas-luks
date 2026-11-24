// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! AES-XTS (IEEE 1619) over the `aes` block cipher, and the AES key wrapper
//! the CBC modes share.
//!
//! Only whole 16-byte blocks are handled: a disk sector is always a multiple
//! of 16 bytes, so ciphertext stealing is not needed. The key is the two AES
//! keys joined, 32 bytes (AES-128-XTS) or 64 bytes (AES-256-XTS).

use aes::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256};

type AesBlock = Block<Aes128>;

/// An AES key of 128 or 256 bits (public for `atlas-bitlocker`'s AES-CCM). The key schedule is wiped when it drops.
#[doc(hidden)]
// One key is held per sector cipher, never in a collection: the size is no cost.
#[allow(clippy::large_enum_variant)]
pub enum AesKey {
    Aes128(Aes128),
    Aes256(Aes256),
}

impl AesKey {
    /// `key` of 16 or 32 bytes, or `None`.
    pub fn new(key: &[u8]) -> Option<Self> {
        match key.len() {
            16 => Aes128::new_from_slice(key).ok().map(Self::Aes128),
            32 => Aes256::new_from_slice(key).ok().map(Self::Aes256),
            _ => None,
        }
    }

    /// Encrypts one 16-byte block in place. Any other length is left alone.
    pub fn encrypt(&self, block: &mut [u8]) {
        if let Ok(b) = <&mut AesBlock>::try_from(block) {
            match self {
                Self::Aes128(k) => k.encrypt_block(b),
                Self::Aes256(k) => k.encrypt_block(b),
            }
        }
    }

    /// Decrypts one 16-byte block in place. Any other length is left alone.
    pub fn decrypt(&self, block: &mut [u8]) {
        if let Ok(b) = <&mut AesBlock>::try_from(block) {
            match self {
                Self::Aes128(k) => k.decrypt_block(b),
                Self::Aes256(k) => k.decrypt_block(b),
            }
        }
    }
}

/// An AES-XTS key.
pub struct Xts {
    data: AesKey,
    tweak: AesKey,
}

impl Xts {
    /// An XTS key of 32 or 64 bytes (two AES keys); `None` for any other
    /// length.
    pub fn new(key: &[u8]) -> Option<Self> {
        if key.len() != 32 && key.len() != 64 {
            return None;
        }
        let (k1, k2) = key.split_at(key.len() / 2);
        Some(Self {
            data: AesKey::new(k1)?,
            tweak: AesKey::new(k2)?,
        })
    }

    /// Decrypts `data` (a whole number of 16-byte blocks; a short tail is
    /// left as it is) as the data unit numbered `unit`, the way dm-crypt's
    /// `plain64` IV does: the tweak is the number as 16 little-endian bytes.
    pub fn decrypt_sector(&self, unit: u64, data: &mut [u8]) {
        self.decrypt_with_tweak(tweak_of(unit), data);
    }

    /// Decrypts `data` with the data unit number `tweak` (16 bytes, as given
    /// to the cipher before it is encrypted).
    pub fn decrypt_with_tweak(&self, tweak: [u8; 16], data: &mut [u8]) {
        let mut t = tweak;
        self.tweak.encrypt(&mut t);
        for block in data.as_chunks_mut::<16>().0.iter_mut() {
            xor16(block, &t);
            self.data.decrypt(block);
            xor16(block, &t);
            t = double(t);
        }
    }

    /// The inverse of [`Self::decrypt_with_tweak`], for building test data.
    #[cfg(any(test, feature = "test-util"))]
    pub fn encrypt_with_tweak(&self, tweak: [u8; 16], data: &mut [u8]) {
        let mut t = tweak;
        self.tweak.encrypt(&mut t);
        for block in data.as_chunks_mut::<16>().0.iter_mut() {
            xor16(block, &t);
            self.data.encrypt(block);
            xor16(block, &t);
            t = double(t);
        }
    }
}

/// The plain64 tweak of data unit `unit`.
#[doc(hidden)]
pub fn tweak_of(unit: u64) -> [u8; 16] {
    let mut t = [0u8; 16];
    for (dst, src) in t.iter_mut().zip(unit.to_le_bytes()) {
        *dst = src;
    }
    t
}

fn xor16(block: &mut [u8], t: &[u8; 16]) {
    for (b, k) in block.iter_mut().zip(t) {
        *b ^= *k;
    }
}

/// Multiplies the tweak by x in GF(2^128) with the XTS polynomial
/// (x^128 + x^7 + x^2 + x + 1), little-endian.
fn double(t: [u8; 16]) -> [u8; 16] {
    let v = u128::from_le_bytes(t);
    let carry = v.rotate_left(1) & 1;
    let shifted = v.wrapping_shl(1);
    let reduced = if carry == 1 { shifted ^ 0x87 } else { shifted };
    reduced.to_le_bytes()
}
