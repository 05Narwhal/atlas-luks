// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Key derivation for LUKS: the hash specs, PBKDF2-HMAC, Argon2 with fallible
//! memory, and the anti-forensic (AF) merge.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

use super::{bad_field, clip, corrupt};
use atlas_fs_core::error::{CorruptKind, Error, Result};

/// A hash a LUKS header can name, for PBKDF2, the AF diffusion and digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    /// SHA-1 (20 bytes).
    Sha1,
    /// SHA-256 (32 bytes).
    Sha256,
    /// SHA-512 (64 bytes).
    Sha512,
}

/// The largest output of any [`Hash`].
const MAX_DIGEST: usize = 64;

impl Hash {
    /// The hash called `name` in a header. Anything but sha1, sha256 and
    /// sha512 (ripemd160, whirlpool, ...) is `Error::Unsupported`.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            other => Err(Error::unsupported(format!("hash {}", clip(other)))),
        }
    }

    /// Output size in bytes.
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// Hashes the concatenation of `parts` into the start of `out` and
    /// returns the number of bytes written.
    fn digest(self, parts: &[&[u8]], out: &mut [u8; MAX_DIGEST]) -> usize {
        fn run<D: Digest>(parts: &[&[u8]], out: &mut [u8; MAX_DIGEST]) -> usize {
            let mut d = D::new();
            for part in parts {
                d.update(part);
            }
            let result = d.finalize();
            let n = result.len().min(MAX_DIGEST);
            for (dst, src) in out.iter_mut().zip(result.iter()) {
                *dst = *src;
            }
            n
        }
        match self {
            Self::Sha1 => run::<Sha1>(parts, out),
            Self::Sha256 => run::<Sha256>(parts, out),
            Self::Sha512 => run::<Sha512>(parts, out),
        }
    }
}

/// The plain digest of `data` into `out` (at most the hash's output size is
/// written).
pub fn digest_into(hash: Hash, data: &[u8], out: &mut [u8]) {
    let mut full = Zeroizing::new([0u8; MAX_DIGEST]);
    let n = hash.digest(&[data], &mut full);
    for (dst, src) in out.iter_mut().zip(full.iter().take(n)) {
        *dst = *src;
    }
}

/// PBKDF2-HMAC of `password` and `salt` with `iterations` rounds into `out`.
///
/// The caller has already checked `iterations` against its limit; zero is
/// treated as one round.
pub fn pbkdf2(hash: Hash, password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let rounds = iterations.max(1);
    match hash {
        Hash::Sha1 => pbkdf2::pbkdf2_hmac::<Sha1>(password, salt, rounds, out),
        Hash::Sha256 => pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, rounds, out),
        Hash::Sha512 => pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, rounds, out),
    }
}

/// Argon2 (`id` or `i`, version 1.3) of `password` and `salt` into `out`.
///
/// `memory_kib`, `time` and `cpus` were checked against the caller's limits.
/// The work memory is allocated fallibly and wiped before it is freed; an
/// allocation that fails is `Error::Unsupported`.
pub fn argon2(
    id: bool,
    password: &[u8],
    salt: &[u8],
    time: u32,
    memory_kib: u32,
    cpus: u32,
    out: &mut [u8],
) -> Result<()> {
    const STRUCTURE: &str = "LUKS2 argon2 parameters";
    let params = Params::new(memory_kib, time, cpus, Some(out.len()))
        .map_err(|_| bad_field(STRUCTURE, "memory, time or cpus", u64::from(memory_kib)))?;
    let algorithm = if id {
        Algorithm::Argon2id
    } else {
        Algorithm::Argon2i
    };
    let blocks = params.block_count();
    let argon = Argon2::new(algorithm, Version::V0x13, params);
    let mut memory: Vec<Block> = Vec::new();
    memory
        .try_reserve_exact(blocks)
        .map_err(|_| Error::unsupported("not enough memory for the key derivation"))?;
    memory.resize(blocks, Block::new());
    let result = argon.hash_password_into_with_memory(password, salt, out, memory.as_mut_slice());
    memory.zeroize();
    result.map_err(|_| bad_field(STRUCTURE, "salt or output length", salt.len() as u64))
}

/// The AF merge of LUKS: folds `stripes` blocks of `block_size` bytes of
/// `material` back into one block, the key.
///
/// `material` holds at least `block_size * stripes` bytes.
pub fn af_merge(
    hash: Hash,
    material: &[u8],
    block_size: usize,
    stripes: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    const STRUCTURE: &str = "LUKS key material";
    let total = block_size
        .checked_mul(stripes)
        .filter(|&n| n != 0 && n <= material.len())
        .ok_or_else(|| bad_field(STRUCTURE, "stripes", stripes as u64))?;
    let mut acc = Zeroizing::new(vec![0u8; block_size]);
    let mut blocks = material
        .get(..total)
        .ok_or_else(|| corrupt(STRUCTURE, CorruptKind::Other("key material is short")))?
        .chunks_exact(block_size);
    for _ in 1..stripes {
        let block = blocks
            .next()
            .ok_or_else(|| corrupt(STRUCTURE, CorruptKind::Other("key material is short")))?;
        xor_into(&mut acc, block);
        diffuse(hash, &mut acc);
    }
    let last = blocks
        .next()
        .ok_or_else(|| corrupt(STRUCTURE, CorruptKind::Other("key material is short")))?;
    xor_into(&mut acc, last);
    Ok(acc)
}

fn xor_into(acc: &mut [u8], block: &[u8]) {
    for (a, b) in acc.iter_mut().zip(block) {
        *a ^= *b;
    }
}

/// The diffusion of the AF scheme: every digest-sized piece of `buf` is
/// replaced by the hash of its index (big-endian u32) and itself; a short
/// last piece takes the front of its hash.
fn diffuse(hash: Hash, buf: &mut [u8]) {
    let mut out = Zeroizing::new([0u8; MAX_DIGEST]);
    for (index, piece) in buf.chunks_mut(hash.output_len()).enumerate() {
        // At most 128 pieces (a key is at most 128 bytes): fits.
        let index = u32::try_from(index).unwrap_or(u32::MAX);
        hash.digest(&[&index.to_be_bytes(), piece], &mut out);
        let n = piece.len();
        for (dst, src) in piece.iter_mut().zip(out.iter().take(n)) {
            *dst = *src;
        }
    }
}

/// True when `a` and `b` hold the same bytes; takes the same time for any
/// content of equal length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The splitting half of the AF scheme, to check the merge against.
    fn af_split(hash: Hash, key: &[u8], stripes: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut acc = vec![0u8; key.len()];
        let mut state = 0x1234_5678_9abc_def0u64;
        for _ in 1..stripes {
            let block: Vec<u8> = (0..key.len())
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    (state >> 24) as u8
                })
                .collect();
            xor_into(&mut acc, &block);
            diffuse(hash, &mut acc);
            out.extend(block);
        }
        xor_into(&mut acc, key);
        out.extend(acc);
        out
    }

    #[test]
    fn af_merge_inverts_split() {
        for hash in [Hash::Sha1, Hash::Sha256, Hash::Sha512] {
            // 100 bytes is not a multiple of any digest size: the short last piece.
            for size in [16usize, 32, 48, 64, 100, 1] {
                for stripes in [1usize, 2, 10, 50] {
                    let key: Vec<u8> = (0..size).map(|i| (i * 31 + 7) as u8).collect();
                    let material = af_split(hash, &key, stripes);
                    let merged = af_merge(hash, &material, size, stripes).unwrap();
                    assert_eq!(&*merged, &key[..], "{hash:?} {size} {stripes}");
                }
            }
        }
    }

    #[test]
    fn af_merge_checks_its_arguments() {
        let material = vec![0u8; 64];
        assert!(af_merge(Hash::Sha256, &material, 32, 0).is_err());
        assert!(af_merge(Hash::Sha256, &material, 0, 4).is_err());
        assert!(af_merge(Hash::Sha256, &material, 32, 3).is_err());
        assert!(af_merge(Hash::Sha256, &material, usize::MAX, 2).is_err());
        assert!(af_merge(Hash::Sha256, &material, 32, usize::MAX).is_err());
        assert!(af_merge(Hash::Sha256, &material, 32, 2).is_ok());
    }

    #[test]
    fn pbkdf2_known_answers() {
        // RFC 6070 for SHA-1, and the widely published SHA-256 answer for the same input.
        let mut out = [0u8; 20];
        pbkdf2(Hash::Sha1, b"password", b"salt", 1, &mut out);
        assert_eq!(hex(&out), "0c60c80f961f0e71f3a9b524af6012062fe037a6");
        pbkdf2(Hash::Sha1, b"password", b"salt", 2, &mut out);
        assert_eq!(hex(&out), "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
        pbkdf2(Hash::Sha256, b"password", b"salt", 1, &mut out);
        assert_eq!(hex(&out), "120fb6cffcf8b32c43e7225256c4f837a86548c9");
    }

    #[test]
    fn digests_and_names() {
        let mut out = [0u8; 32];
        digest_into(Hash::Sha256, b"abc", &mut out);
        assert_eq!(
            hex(&out),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(Hash::parse("sha512").unwrap().output_len(), 64);
        assert!(matches!(
            Hash::parse("ripemd160"),
            Err(Error::Unsupported(_))
        ));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn argon2_rejects_what_it_cannot_run() {
        let mut out = [0u8; 32];
        // Memory below 8 blocks per lane, a salt under 8 bytes.
        assert!(argon2(true, b"pw", &[0u8; 16], 1, 4, 1, &mut out).is_err());
        assert!(argon2(true, b"pw", &[0u8; 4], 1, 64, 1, &mut out).is_err());
        assert!(argon2(true, b"pw", &[0u8; 16], 1, 64, 1, &mut out).is_ok());
        // The two variants differ.
        let mut other = [0u8; 32];
        argon2(false, b"pw", &[0u8; 16], 1, 64, 1, &mut other).unwrap();
        assert_ne!(out, other);
    }
}
