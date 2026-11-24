// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! LUKS1 and LUKS2: reading the header, finding the volume key from a
//! password, and mounting what is inside.
//!
//! The header is hostile input. Every size, offset and count is checked
//! against the source and against the limits below before it is used;
//! nothing allocates from an unchecked value; the key derivation costs a
//! header asks for are capped ([`Limits`]) and an over-expensive keyslot is
//! skipped, not run.
//!
//! LUKS1: the header is 592 bytes at 0 (big-endian). A keyslot's key is
//! PBKDF2(password, slot salt); it decrypts the slot's key material, which
//! the anti-forensic merge folds into the candidate master key; the key is
//! right when PBKDF2(master key, digest salt) matches the header's digest.
//!
//! LUKS2: a 4 KiB binary header, then a JSON area, twice (at 0 and again
//! right after it); a checksum covers both. The JSON describes keyslots,
//! digests and the data segment. Unlocking is the same dance per keyslot,
//! with PBKDF2 or Argon2 as the keyslot's KDF.

use std::sync::Arc;

use base64::Engine as _;
use serde_json::Value;
use zeroize::Zeroizing;

use super::kdf::{self, Hash, ct_eq};
use super::source::{Decrypted, SectorCipher};
use super::{bad_field, clip, corrupt, out_of_range};
use atlas_fs_core::error::{CorruptKind, Error, Result};
use atlas_fs_core::fs::{ContainerVolume, FileSystem, LockedVolume, VolumeState};
use atlas_fs_core::io::block::BlockSource;

const V1_STRUCTURE: &str = "LUKS1 header";
const V2_STRUCTURE: &str = "LUKS2 header";
const JSON_STRUCTURE: &str = "LUKS2 metadata";

/// The signature of a primary header.
const MAGIC: [u8; 6] = *b"LUKS\xba\xbe";
/// The signature of a secondary (backup) LUKS2 header.
const MAGIC_SECONDARY: [u8; 6] = *b"SKUL\xba\xbe";

/// Size of a LUKS1 header, with its eight keyslots.
const V1_HEADER: usize = 592;
/// A LUKS1 keyslot is marked active with this value.
const V1_SLOT_ACTIVE: u32 = 0x00AC_71F3;
/// LUKS1 counts keyslot offsets and the payload offset in these sectors.
const V1_SECTOR: u64 = 512;
/// Size of the LUKS2 binary header.
const V2_BINARY: usize = 4096;
/// Where the checksum sits in the LUKS2 binary header, and how long it is.
const V2_CSUM_AT: usize = 448;
const V2_CSUM_LEN: usize = 64;

/// Most keyslots (and digests) examined.
pub const MAX_KEYSLOTS: usize = 32;
/// Largest key (volume key or keyslot area key) in bytes.
pub const MAX_KEY_BYTES: u64 = 128;
/// Most anti-forensic stripes in a keyslot.
pub const MAX_STRIPES: u64 = 4000;
/// Largest LUKS2 JSON area.
pub const MAX_JSON_BYTES: u64 = 4 << 20;
/// Smallest and largest LUKS2 header (binary header plus JSON area).
const MIN_V2_HEADER: u64 = 16 << 10;
const MAX_V2_HEADER: u64 = 4 << 20;
/// Longest salt or digest read from the metadata.
const MAX_BLOB: usize = 1024;

/// Caps on the work a header may ask of an unlock.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Most PBKDF2 iterations of one derivation.
    pub pbkdf2_iterations: u32,
    /// Most PBKDF2 iterations over a whole unlock.
    pub pbkdf2_total: u64,
    /// Most Argon2 memory, in KiB.
    pub argon2_memory_kib: u32,
    /// Most Argon2 passes.
    pub argon2_time: u32,
    /// Most Argon2 lanes.
    pub argon2_cpus: u32,
    /// Most Argon2 work over a whole unlock: memory in KiB times passes,
    /// summed over the keyslots tried.
    pub argon2_total: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            pbkdf2_iterations: 20_000_000,
            pbkdf2_total: 160_000_000,
            argon2_memory_kib: 2 * 1024 * 1024,
            argon2_time: 100,
            argon2_cpus: 64,
            // 16 passes over the largest allowed memory.
            argon2_total: 16 * 2 * 1024 * 1024,
        }
    }
}

/// What the work caps count down during one unlock.
struct Budget {
    pbkdf2_left: u64,
    argon2_left: u64,
}

impl Budget {
    /// Spends `iterations` of a PBKDF2 that makes `out_len` bytes with `hash`
    /// (every output block repeats all iterations); false when the unlock has
    /// no more to spend.
    fn take(&mut self, hash: Hash, out_len: usize, iterations: u32) -> bool {
        let blocks = out_len.div_ceil(hash.output_len().max(1)).max(1) as u64;
        let cost = u64::from(iterations).saturating_mul(blocks);
        match self.pbkdf2_left.checked_sub(cost) {
            Some(left) => {
                self.pbkdf2_left = left;
                true
            }
            None => false,
        }
    }

    /// Spends one Argon2 run of `memory_kib` and `time` passes.
    fn take_argon2(&mut self, memory_kib: u32, time: u32) -> bool {
        let cost = u64::from(memory_kib).saturating_mul(u64::from(time.max(1)));
        match self.argon2_left.checked_sub(cost) {
            Some(left) => {
                self.argon2_left = left;
                true
            }
            None => false,
        }
    }
}

/// True when `head` (the start of a source) holds a LUKS header of version 1
/// or 2.
pub fn is_luks(head: &[u8]) -> bool {
    head.get(..6) == Some(&MAGIC[..])
        && matches!(
            head.get(6..8).and_then(|v| <[u8; 2]>::try_from(v).ok()),
            Some([0, 1]) | Some([0, 2])
        )
}

/// Mounts the decrypted payload of a volume: the engine's probe and mount,
/// supplied by the caller because this crate reads no filesystem itself.
pub type Mounter = fn(Arc<dyn BlockSource>) -> Result<Arc<dyn FileSystem>>;

/// Mounts a source that starts with a LUKS header: one locked volume. Its
/// `unlock` decrypts the payload and hands it to `mounter`.
///
/// A header that cannot be used (damaged, or a cipher or feature this reader
/// does not have) is a volume in the `Failed` state; a read error is an
/// error.
pub fn mount(source: Arc<dyn BlockSource>, mounter: Mounter) -> Result<Vec<ContainerVolume>> {
    match open(source) {
        Ok(luks) => Ok(vec![ContainerVolume::new(
            "",
            None,
            VolumeState::Locked(Arc::new(LockedLuks { luks, mounter })),
        )]),
        Err(e @ (Error::Io { .. } | Error::AccessDenied { .. })) => Err(e),
        Err(e) => Ok(vec![ContainerVolume::new("", None, VolumeState::Failed(e))]),
    }
}

/// Reads the LUKS header of `source` with the default [`Limits`].
pub fn open(source: Arc<dyn BlockSource>) -> Result<Luks> {
    open_with_limits(source, Limits::default())
}

/// Reads the LUKS header of `source`.
pub fn open_with_limits(source: Arc<dyn BlockSource>, limits: Limits) -> Result<Luks> {
    let header = read_header(&*source)?;
    Ok(Luks {
        source,
        header,
        limits,
    })
}

/// A LUKS volume waiting for its password. Holds the parsed header and the
/// source, never a password or a key.
pub struct Luks {
    source: Arc<dyn BlockSource>,
    header: Header,
    limits: Limits,
}

impl Luks {
    /// 1 or 2.
    pub fn version(&self) -> u8 {
        match self.header {
            Header::V1(_) => 1,
            Header::V2(_) => 2,
        }
    }

    /// The decrypted payload, when `password` opens a keyslot. The password
    /// and every key made on the way are wiped before this returns, except
    /// the volume key inside the returned source.
    pub fn unlock_source(&self, password: &str) -> Result<Arc<dyn BlockSource>> {
        let password = Zeroizing::new(password.as_bytes().to_vec());
        let mut budget = Budget {
            pbkdf2_left: self.limits.pbkdf2_total,
            argon2_left: self.limits.argon2_total,
        };
        let decrypted = match &self.header {
            Header::V1(h) => self.unlock_v1(h, &password, &mut budget)?,
            Header::V2(h) => self.unlock_v2(h, &password, &mut budget)?,
        };
        Ok(Arc::new(decrypted))
    }

    fn unlock_v1(&self, h: &V1, password: &[u8], budget: &mut Budget) -> Result<Decrypted> {
        let mut outcome = Outcome::default();
        for slot in &h.slots {
            let attempt = self.try_v1_slot(h, slot, password, budget);
            if let Some(master) = outcome.record(attempt)? {
                let cipher = SectorCipher::parse(&h.cipher, &master)?;
                return Decrypted::new(
                    Arc::clone(&self.source),
                    cipher,
                    h.payload_start,
                    h.payload_len,
                    512,
                    0,
                    1,
                );
            }
        }
        Err(outcome.finish())
    }

    /// One LUKS1 keyslot: `Ok(Some(master key))` when the password opens it,
    /// `Ok(None)` when it does not.
    fn try_v1_slot(
        &self,
        h: &V1,
        slot: &V1Slot,
        password: &[u8],
        budget: &mut Budget,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let limit = self.limits.pbkdf2_iterations;
        if slot.iterations == 0
            || slot.iterations > limit
            || !budget.take(h.hash, h.key_bytes, slot.iterations)
        {
            return Err(too_expensive());
        }
        if h.mk_iterations > limit || !budget.take(h.hash, 20, h.mk_iterations) {
            return Err(too_expensive());
        }
        let mut derived = Zeroizing::new(vec![0u8; h.key_bytes]);
        kdf::pbkdf2(h.hash, password, &slot.salt, slot.iterations, &mut derived);
        let material = read_key_material(
            &*self.source,
            slot.offset,
            h.key_bytes,
            slot.stripes,
            &h.cipher,
            &derived,
        )?;
        let master = kdf::af_merge(h.hash, &material, h.key_bytes, slot.stripes)?;
        let mut check = [0u8; 20];
        kdf::pbkdf2(h.hash, &master, &h.mk_salt, h.mk_iterations, &mut check);
        Ok(ct_eq(&check, &h.mk_digest).then_some(master))
    }

    fn unlock_v2(&self, h: &V2, password: &[u8], budget: &mut Budget) -> Result<Decrypted> {
        let mut outcome = Outcome::default();
        for slot in &h.slots {
            let attempt = self.try_v2_slot(h, slot, password, budget);
            if let Some(key) = outcome.record(attempt)? {
                let seg = &h.segment;
                let cipher = SectorCipher::parse(&seg.cipher, &key)?;
                return Decrypted::new(
                    Arc::clone(&self.source),
                    cipher,
                    seg.offset,
                    seg.len,
                    seg.sector_size,
                    seg.iv_tweak,
                    seg.iv_step,
                );
            }
        }
        Err(outcome.finish())
    }

    fn try_v2_slot(
        &self,
        h: &V2,
        slot: &V2Slot,
        password: &[u8],
        budget: &mut Budget,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let digest = h
            .digests
            .get(slot.digest)
            .ok_or_else(|| bad_field(JSON_STRUCTURE, "digest", slot.digest as u64))?;
        let limits = &self.limits;
        let digest_iterations = u32::try_from(digest.iterations)
            .ok()
            .filter(|&n| n != 0 && n <= limits.pbkdf2_iterations)
            .ok_or_else(too_expensive)?;
        let mut area_key = Zeroizing::new(vec![0u8; slot.area_key_size]);
        match &slot.kdf {
            Kdf::Pbkdf2 {
                hash,
                iterations,
                salt,
            } => {
                let n = u32::try_from(*iterations)
                    .ok()
                    .filter(|&n| n != 0 && n <= limits.pbkdf2_iterations)
                    .ok_or_else(too_expensive)?;
                if !budget.take(*hash, slot.area_key_size, n) {
                    return Err(too_expensive());
                }
                kdf::pbkdf2(*hash, password, salt, n, &mut area_key);
            }
            Kdf::Argon2 {
                id,
                time,
                memory,
                cpus,
                salt,
            } => {
                let costs = (
                    u32::try_from(*time)
                        .ok()
                        .filter(|&n| n <= limits.argon2_time),
                    u32::try_from(*memory)
                        .ok()
                        .filter(|&n| n <= limits.argon2_memory_kib),
                    u32::try_from(*cpus)
                        .ok()
                        .filter(|&n| n <= limits.argon2_cpus),
                );
                let (Some(time), Some(memory), Some(cpus)) = costs else {
                    return Err(too_expensive());
                };
                if !budget.take_argon2(memory, time) {
                    return Err(too_expensive());
                }
                kdf::argon2(*id, password, salt, time, memory, cpus, &mut area_key)?;
            }
        }
        if !budget.take(digest.hash, digest.digest.len(), digest_iterations) {
            return Err(too_expensive());
        }
        let material = read_key_material(
            &*self.source,
            slot.area_offset,
            slot.key_size,
            slot.stripes,
            &slot.area_cipher,
            &area_key,
        )?;
        let key = kdf::af_merge(slot.af_hash, &material, slot.key_size, slot.stripes)?;
        let mut check = Zeroizing::new(vec![0u8; digest.digest.len()]);
        kdf::pbkdf2(
            digest.hash,
            &key,
            &digest.salt,
            digest_iterations,
            &mut check,
        );
        Ok(ct_eq(&check, &digest.digest).then_some(key))
    }
}

/// A [`Luks`] with the mounter that opens what is inside it.
struct LockedLuks {
    luks: Luks,
    mounter: Mounter,
}

impl LockedVolume for LockedLuks {
    fn hint(&self) -> Option<String> {
        None
    }

    fn unlock(&self, password: &str) -> Result<Arc<dyn FileSystem>> {
        let payload = self.luks.unlock_source(password)?;
        (self.mounter)(payload)
    }
}

fn too_expensive() -> Error {
    Error::unsupported("key derivation too expensive")
}

/// What the keyslots of one unlock turned up, to pick the error at the end.
#[derive(Default)]
struct Outcome {
    /// A keyslot ran to the end and its digest did not match.
    mismatched: bool,
    /// The first keyslot that could not be tried.
    skipped: Option<Error>,
}

impl Outcome {
    /// Folds in one keyslot's result: the key when found, `None` to go on,
    /// or an error that ends the unlock (a read error).
    fn record(
        &mut self,
        attempt: Result<Option<Zeroizing<Vec<u8>>>>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match attempt {
            Ok(Some(key)) => Ok(Some(key)),
            Ok(None) => {
                self.mismatched = true;
                Ok(None)
            }
            Err(e @ (Error::Io { .. } | Error::AccessDenied { .. })) => Err(e),
            Err(e) => {
                self.skipped.get_or_insert(e);
                Ok(None)
            }
        }
    }

    /// The error when no keyslot opened: the password was wrong if any slot
    /// could be tried, else the reason none could.
    fn finish(self) -> Error {
        if self.mismatched {
            Error::WrongPassword
        } else {
            self.skipped.unwrap_or(Error::WrongPassword)
        }
    }
}

/// Reads `key_bytes * stripes` bytes of key material at `offset` (in whole
/// 512-byte sectors) and decrypts them with `cipher` keyed with `key`, the
/// way a keyslot area is: sector numbers count from the start of the area.
fn read_key_material(
    source: &dyn BlockSource,
    offset: u64,
    key_bytes: usize,
    stripes: usize,
    cipher: &str,
    key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let need = key_bytes
        .checked_mul(stripes)
        .and_then(|n| n.checked_next_multiple_of(512))
        .ok_or_else(|| bad_field(V1_STRUCTURE, "stripes", stripes as u64))?;
    let mut buf = Zeroizing::new(Vec::new());
    buf.try_reserve_exact(need)
        .map_err(|_| Error::unsupported("not enough memory for the key material"))?;
    buf.resize(need, 0);
    source.read_at(offset, &mut buf)?;
    let cipher = SectorCipher::parse(cipher, key)?;
    for (number, sector) in (0u64..).zip(buf.as_chunks_mut::<512>().0.iter_mut()) {
        cipher.decrypt_sector(number, sector);
    }
    Ok(buf)
}

// ---------------------------------------------------------------- parsing

enum Header {
    V1(V1),
    V2(V2),
}

struct V1 {
    /// `cipher_name-cipher_mode`, such as `aes-xts-plain64`.
    cipher: String,
    hash: Hash,
    payload_start: u64,
    payload_len: u64,
    key_bytes: usize,
    mk_digest: [u8; 20],
    mk_salt: [u8; 32],
    mk_iterations: u32,
    slots: Vec<V1Slot>,
}

struct V1Slot {
    iterations: u32,
    salt: [u8; 32],
    /// Byte offset of the key material.
    offset: u64,
    stripes: usize,
}

struct V2 {
    /// Usable keyslots, high priority first.
    slots: Vec<V2Slot>,
    digests: Vec<V2Digest>,
    segment: V2Segment,
}

struct V2Slot {
    key_size: usize,
    stripes: usize,
    af_hash: Hash,
    area_offset: u64,
    area_key_size: usize,
    area_cipher: String,
    kdf: Kdf,
    /// Index into `V2::digests`.
    digest: usize,
}

enum Kdf {
    Pbkdf2 {
        hash: Hash,
        iterations: u64,
        salt: Vec<u8>,
    },
    Argon2 {
        id: bool,
        time: u64,
        memory: u64,
        cpus: u64,
        salt: Vec<u8>,
    },
}

struct V2Digest {
    hash: Hash,
    iterations: u64,
    salt: Vec<u8>,
    digest: Vec<u8>,
}

struct V2Segment {
    offset: u64,
    len: u64,
    sector_size: u32,
    iv_tweak: u64,
    /// How much the IV number grows from one sector to the next.
    iv_step: u64,
    cipher: String,
}

/// `value` as a `usize`, or a range error.
fn to_usize(structure: &'static str, field: &'static str, value: u64) -> Result<usize> {
    usize::try_from(value)
        .map_err(|_| out_of_range(structure, field, value, "limit", u64::from(u32::MAX)))
}

/// `n` rounded down to a multiple of `unit` (`unit` is not zero).
fn round_down(n: u64, unit: u64) -> u64 {
    n.checked_div(unit).unwrap_or(0).saturating_mul(unit)
}

/// The bytes read for `stripes` stripes of a `key_bytes` key: whole 512-byte
/// sectors.
fn material_size(key_bytes: u64, stripes: u64) -> Option<u64> {
    key_bytes
        .checked_mul(stripes)?
        .checked_next_multiple_of(512)
}

fn truncated(structure: &'static str, needed: u64, available: u64) -> Error {
    corrupt(structure, CorruptKind::Truncated { needed, available })
}

/// `N` bytes of `buf` at `at`.
fn array<const N: usize>(structure: &'static str, buf: &[u8], at: usize) -> Result<[u8; N]> {
    at.checked_add(N)
        .and_then(|end| buf.get(at..end))
        .and_then(|b| <[u8; N]>::try_from(b).ok())
        .ok_or_else(|| {
            truncated(
                structure,
                (at as u64).saturating_add(N as u64),
                buf.len() as u64,
            )
        })
}

/// A NUL-terminated ASCII field.
fn c_string<'a>(structure: &'static str, field: &'static str, bytes: &'a [u8]) -> Result<&'a str> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let text = bytes.get(..end).unwrap_or_default();
    std::str::from_utf8(text).map_err(|_| bad_field(structure, field, 0))
}

fn read_header(source: &dyn BlockSource) -> Result<Header> {
    let len = source.len();
    let mut head = [0u8; 8];
    if len < 8 {
        return Err(truncated(V1_STRUCTURE, 8, len));
    }
    source.read_at(0, &mut head)?;
    if !is_luks(&head) {
        let found = u64::from_be_bytes(head);
        return Err(corrupt(
            V1_STRUCTURE,
            CorruptKind::BadSignature {
                expected: u64::from_be_bytes([b'L', b'U', b'K', b'S', 0xba, 0xbe, 0, 1]),
                found,
            },
        ));
    }
    if head[7] == 1 {
        read_v1(source).map(Header::V1)
    } else {
        read_v2(source).map(Header::V2)
    }
}

// ------------------------------------------------------------------ LUKS1

fn read_v1(source: &dyn BlockSource) -> Result<V1> {
    let len = source.len();
    if len < V1_HEADER as u64 {
        return Err(truncated(V1_STRUCTURE, V1_HEADER as u64, len));
    }
    let mut b = vec![0u8; V1_HEADER];
    source.read_at(0, &mut b)?;
    let name = c_string(
        V1_STRUCTURE,
        "cipher name",
        b.get(8..40).unwrap_or_default(),
    )?;
    let mode = c_string(
        V1_STRUCTURE,
        "cipher mode",
        b.get(40..72).unwrap_or_default(),
    )?;
    let hash = Hash::parse(c_string(
        V1_STRUCTURE,
        "hash spec",
        b.get(72..104).unwrap_or_default(),
    )?)?;
    let payload_sectors = u64::from(u32::from_be_bytes(array(V1_STRUCTURE, &b, 104)?));
    let key_bytes = u64::from(u32::from_be_bytes(array(V1_STRUCTURE, &b, 108)?));
    if key_bytes == 0 || key_bytes > MAX_KEY_BYTES {
        return Err(out_of_range(
            V1_STRUCTURE,
            "key bytes",
            key_bytes,
            "limit",
            MAX_KEY_BYTES,
        ));
    }
    let key_bytes = to_usize(V1_STRUCTURE, "key bytes", key_bytes)?;
    let cipher = format!("{name}-{mode}");
    // Fail now, naming the cipher, rather than after the password is typed.
    SectorCipher::parse(&cipher, &vec![0u8; key_bytes])?;
    let mk_digest: [u8; 20] = array(V1_STRUCTURE, &b, 112)?;
    let mk_salt: [u8; 32] = array(V1_STRUCTURE, &b, 132)?;
    let mk_iterations = u32::from_be_bytes(array(V1_STRUCTURE, &b, 164)?);
    if mk_iterations == 0 {
        return Err(bad_field(V1_STRUCTURE, "mk digest iterations", 0));
    }
    let payload_start = payload_sectors
        .checked_mul(V1_SECTOR)
        .filter(|&start| start < len)
        .ok_or_else(|| {
            out_of_range(
                V1_STRUCTURE,
                "payload offset",
                payload_sectors,
                "source sectors",
                len / V1_SECTOR,
            )
        })?;
    let payload_len = round_down(len.saturating_sub(payload_start), V1_SECTOR);
    if payload_len == 0 {
        return Err(bad_field(V1_STRUCTURE, "payload offset", payload_sectors));
    }

    let mut slots = Vec::new();
    for i in 0..8usize {
        let at = 208usize.saturating_add(i.saturating_mul(48));
        let state = u32::from_be_bytes(array(V1_STRUCTURE, &b, at)?);
        if state != V1_SLOT_ACTIVE {
            continue;
        }
        let iterations = u32::from_be_bytes(array(V1_STRUCTURE, &b, at.saturating_add(4))?);
        let salt: [u8; 32] = array(V1_STRUCTURE, &b, at.saturating_add(8))?;
        let material_sectors = u64::from(u32::from_be_bytes(array(
            V1_STRUCTURE,
            &b,
            at.saturating_add(40),
        )?));
        let stripes = u64::from(u32::from_be_bytes(array(
            V1_STRUCTURE,
            &b,
            at.saturating_add(44),
        )?));
        if stripes == 0 || stripes > MAX_STRIPES {
            return Err(out_of_range(
                V1_STRUCTURE,
                "stripes",
                stripes,
                "limit",
                MAX_STRIPES,
            ));
        }
        let offset = material_sectors
            .checked_mul(V1_SECTOR)
            .ok_or_else(|| bad_field(V1_STRUCTURE, "key material offset", material_sectors))?;
        // Whole sectors are read, and they must lie inside the source.
        let size = material_size(key_bytes as u64, stripes)
            .ok_or_else(|| bad_field(V1_STRUCTURE, "stripes", stripes))?;
        match offset.checked_add(size) {
            Some(end) if end <= len => {}
            _ => {
                return Err(out_of_range(
                    V1_STRUCTURE,
                    "key material offset",
                    offset,
                    "source size",
                    len,
                ));
            }
        }
        slots.push(V1Slot {
            iterations,
            salt,
            offset,
            stripes: to_usize(V1_STRUCTURE, "stripes", stripes)?,
        });
    }
    if slots.is_empty() {
        return Err(corrupt(
            V1_STRUCTURE,
            CorruptKind::Other("no active keyslot"),
        ));
    }
    Ok(V1 {
        cipher,
        hash,
        payload_start,
        payload_len,
        key_bytes,
        mk_digest,
        mk_salt,
        mk_iterations,
        slots,
    })
}

// ------------------------------------------------------------------ LUKS2

/// Offsets a header may sit at: the primary, then the secondary copies, which
/// start where the primary's area (its size, 16 KiB to 4 MiB) ends.
fn v2_offsets() -> impl Iterator<Item = u64> {
    std::iter::once(0).chain((0..9u32).map(|k| MIN_V2_HEADER << k))
}

fn read_v2(source: &dyn BlockSource) -> Result<V2> {
    let len = source.len();
    let mut first: Option<Error> = None;
    for offset in v2_offsets() {
        if offset >= len {
            break;
        }
        let attempt = read_v2_at(source, offset).and_then(|json| parse_v2(&json, len));
        match attempt {
            Ok(v2) => return Ok(v2),
            // Damage here may spare the other copy; anything else is final.
            Err(e @ Error::Corrupt(_)) => {
                first.get_or_insert(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(first.unwrap_or_else(|| truncated(V2_STRUCTURE, MIN_V2_HEADER, len)))
}

/// Reads and verifies the header at `offset`; returns its JSON area.
fn read_v2_at(source: &dyn BlockSource, offset: u64) -> Result<Vec<u8>> {
    let len = source.len();
    let mut head = vec![0u8; V2_BINARY];
    match offset.checked_add(V2_BINARY as u64) {
        Some(end) if end <= len => source.read_at(offset, &mut head)?,
        _ => {
            return Err(truncated(
                V2_STRUCTURE,
                V2_BINARY as u64,
                len.saturating_sub(offset),
            ));
        }
    }
    let magic: [u8; 6] = array(V2_STRUCTURE, &head, 0)?;
    let expected = if offset == 0 { MAGIC } else { MAGIC_SECONDARY };
    if magic != expected {
        return Err(corrupt(
            V2_STRUCTURE,
            CorruptKind::BadSignature {
                expected: u64::from_be_bytes([
                    expected[0],
                    expected[1],
                    expected[2],
                    expected[3],
                    expected[4],
                    expected[5],
                    0,
                    0,
                ]),
                found: u64::from_be_bytes([
                    magic[0], magic[1], magic[2], magic[3], magic[4], magic[5], 0, 0,
                ]),
            },
        ));
    }
    let version = u16::from_be_bytes(array(V2_STRUCTURE, &head, 6)?);
    if version != 2 {
        return Err(bad_field(V2_STRUCTURE, "version", u64::from(version)));
    }
    let hdr_size = u64::from_be_bytes(array(V2_STRUCTURE, &head, 8)?);
    if !(MIN_V2_HEADER..=MAX_V2_HEADER).contains(&hdr_size) || hdr_size % 4096 != 0 {
        return Err(out_of_range(
            V2_STRUCTURE,
            "header size",
            hdr_size,
            "maximum",
            MAX_V2_HEADER,
        ));
    }
    if offset != 0 && hdr_size != offset {
        return Err(bad_field(V2_STRUCTURE, "header size", hdr_size));
    }
    let stored_offset = u64::from_be_bytes(array(V2_STRUCTURE, &head, 256)?);
    if stored_offset != offset {
        return Err(bad_field(V2_STRUCTURE, "header offset", stored_offset));
    }
    match offset.checked_add(hdr_size) {
        Some(end) if end <= len => {}
        _ => {
            return Err(truncated(
                V2_STRUCTURE,
                hdr_size,
                len.saturating_sub(offset),
            ));
        }
    }
    let algorithm = c_string(
        V2_STRUCTURE,
        "checksum algorithm",
        head.get(72..104).unwrap_or_default(),
    )?;
    let hash = Hash::parse(algorithm)?;
    let csum: [u8; V2_CSUM_LEN] = array(V2_STRUCTURE, &head, V2_CSUM_AT)?;

    let mut whole = vec![
        0u8;
        usize::try_from(hdr_size).map_err(|_| bad_field(
            V2_STRUCTURE,
            "header size",
            hdr_size
        ))?
    ];
    source.read_at(offset, &mut whole)?;
    if let Some(field) = whole.get_mut(V2_CSUM_AT..V2_CSUM_AT + V2_CSUM_LEN) {
        field.fill(0);
    }
    let mut check = vec![0u8; hash.output_len()];
    // The checksum is the hash itself, taken with the hash's own HMAC-free
    // digest: reuse PBKDF2's hash plumbing through the plain digest.
    hash_all(hash, &whole, &mut check);
    let stored = csum.get(..check.len()).unwrap_or_default();
    if !ct_eq(&check, stored) {
        return Err(corrupt(
            V2_STRUCTURE,
            CorruptKind::Other("header checksum does not match"),
        ));
    }
    let json = whole.get(V2_BINARY..).unwrap_or_default();
    let end = json.iter().position(|&b| b == 0).unwrap_or(json.len());
    if end as u64 > MAX_JSON_BYTES {
        return Err(out_of_range(
            V2_STRUCTURE,
            "JSON size",
            end as u64,
            "limit",
            MAX_JSON_BYTES,
        ));
    }
    Ok(json.get(..end).unwrap_or_default().to_vec())
}

/// The plain digest of `data` into `out`.
fn hash_all(hash: Hash, data: &[u8], out: &mut [u8]) {
    kdf::digest_into(hash, data, out);
}

/// A field of a JSON object.
fn field<'a>(v: &'a Value, key: &'static str) -> Result<&'a Value> {
    v.get(key).ok_or_else(|| bad_field(JSON_STRUCTURE, key, 0))
}

fn number(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s)
            if !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()) =>
        {
            s.parse().ok()
        }
        _ => None,
    }
}

fn num(v: &Value, key: &'static str) -> Result<u64> {
    number(field(v, key)?).ok_or_else(|| bad_field(JSON_STRUCTURE, key, 0))
}

fn opt_num(v: &Value, key: &'static str, default: u64) -> Result<u64> {
    match v.get(key) {
        None => Ok(default),
        Some(value) => number(value).ok_or_else(|| bad_field(JSON_STRUCTURE, key, 0)),
    }
}

fn text<'a>(v: &'a Value, key: &'static str) -> Result<&'a str> {
    field(v, key)?
        .as_str()
        .ok_or_else(|| bad_field(JSON_STRUCTURE, key, 0))
}

fn blob(v: &Value, key: &'static str) -> Result<Vec<u8>> {
    let encoded = text(v, key)?;
    if encoded.len() > MAX_BLOB * 2 {
        return Err(out_of_range(
            JSON_STRUCTURE,
            key,
            encoded.len() as u64,
            "limit",
            (MAX_BLOB * 2) as u64,
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| bad_field(JSON_STRUCTURE, key, 0))?;
    if bytes.is_empty() || bytes.len() > MAX_BLOB {
        return Err(bad_field(JSON_STRUCTURE, key, bytes.len() as u64));
    }
    Ok(bytes)
}

/// A key size from the metadata: 1 to [`MAX_KEY_BYTES`].
fn key_size(v: &Value, key: &'static str) -> Result<usize> {
    let n = num(v, key)?;
    if n == 0 || n > MAX_KEY_BYTES {
        return Err(out_of_range(JSON_STRUCTURE, key, n, "limit", MAX_KEY_BYTES));
    }
    to_usize(JSON_STRUCTURE, key, n)
}

/// The members of the JSON object `v[key]`, at most [`MAX_KEYSLOTS`], by
/// numeric id.
fn members<'a>(v: &'a Value, key: &'static str) -> Result<Vec<(&'a str, &'a Value)>> {
    let object = field(v, key)?
        .as_object()
        .ok_or_else(|| bad_field(JSON_STRUCTURE, key, 0))?;
    let mut list: Vec<(&str, &Value)> = object.iter().map(|(k, v)| (k.as_str(), v)).collect();
    list.sort_by_key(|(id, _)| (id.parse::<u64>().unwrap_or(u64::MAX), id.len()));
    list.truncate(MAX_KEYSLOTS);
    Ok(list)
}

fn parse_v2(json: &[u8], source_len: u64) -> Result<V2> {
    let root: Value = serde_json::from_slice(json).map_err(|_| {
        corrupt(
            JSON_STRUCTURE,
            CorruptKind::Other("the JSON area does not parse"),
        )
    })?;
    // Re-encryption in progress, or a feature a newer cryptsetup added.
    if let Some(config) = root.get("config") {
        let requirements = config.get("requirements").and_then(Value::as_array);
        if requirements.is_some_and(|r| !r.is_empty()) {
            return Err(Error::unsupported(
                "the volume is being re-encrypted or needs a newer LUKS2 feature",
            ));
        }
    }
    let segment = parse_segment(&root, source_len)?;

    let mut digests = Vec::new();
    let mut digest_slots: Vec<Vec<String>> = Vec::new();
    for (_, d) in members(&root, "digests")? {
        let kind = text(d, "type")?;
        if kind != "pbkdf2" {
            return Err(Error::unsupported(format!(
                "key digest type {}",
                clip(kind)
            )));
        }
        let listed: Vec<String> = field(d, "keyslots")?
            .as_array()
            .ok_or_else(|| bad_field(JSON_STRUCTURE, "keyslots", 0))?
            .iter()
            .filter_map(|id| id.as_str().map(str::to_owned))
            .take(MAX_KEYSLOTS)
            .collect();
        digests.push(V2Digest {
            hash: Hash::parse(text(d, "hash")?)?,
            iterations: num(d, "iterations")?,
            salt: blob(d, "salt")?,
            digest: {
                // The digest is as long as the volume key.
                let bytes = blob(d, "digest")?;
                if bytes.len() as u64 > MAX_KEY_BYTES {
                    return Err(out_of_range(
                        JSON_STRUCTURE,
                        "digest",
                        bytes.len() as u64,
                        "limit",
                        MAX_KEY_BYTES,
                    ));
                }
                bytes
            },
        });
        digest_slots.push(listed);
    }

    let mut slots: Vec<(u64, V2Slot)> = Vec::new();
    for (id, ks) in members(&root, "keyslots")? {
        if text(ks, "type")? != "luks2" {
            continue;
        }
        let Some(digest) = digest_slots
            .iter()
            .position(|ids| ids.iter().any(|s| s == id))
        else {
            continue;
        };
        let size = key_size(ks, "key_size")?;
        let af = field(ks, "af")?;
        let stripes = num(af, "stripes")?;
        if stripes == 0 || stripes > MAX_STRIPES {
            return Err(out_of_range(
                JSON_STRUCTURE,
                "stripes",
                stripes,
                "limit",
                MAX_STRIPES,
            ));
        }
        let area = field(ks, "area")?;
        let area_offset = num(area, "offset")?;
        let area_size = num(area, "size")?;
        let area_key_size = key_size(area, "key_size")?;
        let area_cipher = text(area, "encryption")?.to_owned();
        let need = material_size(size as u64, stripes)
            .ok_or_else(|| bad_field(JSON_STRUCTURE, "stripes", stripes))?;
        match area_offset.checked_add(area_size) {
            Some(end) if end <= source_len && need <= area_size => {}
            _ => {
                return Err(out_of_range(
                    JSON_STRUCTURE,
                    "keyslot area",
                    area_offset,
                    "source size",
                    source_len,
                ));
            }
        }
        SectorCipher::parse(&area_cipher, &vec![0u8; area_key_size])?;
        let kdf_json = field(ks, "kdf")?;
        let kdf = match text(kdf_json, "type")? {
            "pbkdf2" => Kdf::Pbkdf2 {
                hash: Hash::parse(text(kdf_json, "hash")?)?,
                iterations: num(kdf_json, "iterations")?,
                salt: blob(kdf_json, "salt")?,
            },
            kind @ ("argon2i" | "argon2id") => Kdf::Argon2 {
                id: kind == "argon2id",
                time: num(kdf_json, "time")?,
                memory: num(kdf_json, "memory")?,
                cpus: num(kdf_json, "cpus")?,
                salt: blob(kdf_json, "salt")?,
            },
            other => {
                return Err(Error::unsupported(format!(
                    "key derivation {}",
                    clip(other)
                )));
            }
        };
        // 2 high, 1 normal (the default), 0 ignore.
        let priority = opt_num(ks, "priority", 1)?;
        slots.push((
            priority,
            V2Slot {
                key_size: size,
                stripes: to_usize(JSON_STRUCTURE, "stripes", stripes)?,
                af_hash: Hash::parse(text(af, "hash")?)?,
                area_offset,
                area_key_size,
                area_cipher,
                kdf,
                digest,
            },
        ));
    }
    if slots.is_empty() {
        return Err(corrupt(
            JSON_STRUCTURE,
            CorruptKind::Other("no usable keyslot"),
        ));
    }
    slots.sort_by_key(|(priority, _)| std::cmp::Reverse(*priority));
    let slots: Vec<V2Slot> = slots.into_iter().map(|(_, s)| s).collect();
    // The segment's cipher must take a key of the size the keyslots make.
    for slot in &slots {
        SectorCipher::parse(&segment.cipher, &vec![0u8; slot.key_size])?;
    }
    Ok(V2 {
        slots,
        digests,
        segment,
    })
}

fn parse_segment(root: &Value, source_len: u64) -> Result<V2Segment> {
    let segments = field(root, "segments")?
        .as_object()
        .ok_or_else(|| bad_field(JSON_STRUCTURE, "segments", 0))?;
    if segments.is_empty() {
        return Err(bad_field(JSON_STRUCTURE, "segments", 0));
    }
    if segments.len() != 1 {
        return Err(Error::unsupported(
            "LUKS2 volume with more than one data segment (re-encryption)",
        ));
    }
    let Some(seg) = segments.values().next() else {
        return Err(bad_field(JSON_STRUCTURE, "segments", 0));
    };
    let kind = text(seg, "type")?;
    if kind != "crypt" {
        return Err(Error::unsupported(format!(
            "LUKS2 segment type {}",
            clip(kind)
        )));
    }
    if seg.get("integrity").is_some() {
        return Err(Error::unsupported(
            "LUKS2 volume with integrity (authenticated encryption)",
        ));
    }
    if seg
        .get("flags")
        .and_then(Value::as_array)
        .is_some_and(|f| !f.is_empty())
    {
        return Err(Error::unsupported("LUKS2 segment is being re-encrypted"));
    }
    let offset = num(seg, "offset")?;
    let sector_size = u32::try_from(num(seg, "sector_size")?)
        .ok()
        .filter(|s| matches!(s, 512 | 1024 | 2048 | 4096))
        .ok_or_else(|| bad_field(JSON_STRUCTURE, "sector_size", 0))?;
    let sector = u64::from(sector_size);
    if offset >= source_len {
        return Err(out_of_range(
            JSON_STRUCTURE,
            "segment offset",
            offset,
            "source size",
            source_len,
        ));
    }
    let len = match field(seg, "size")? {
        Value::String(s) if s == "dynamic" => round_down(source_len.saturating_sub(offset), sector),
        other => {
            let size = number(other).ok_or_else(|| bad_field(JSON_STRUCTURE, "size", 0))?;
            match offset.checked_add(size) {
                Some(end) if end <= source_len && size.is_multiple_of(sector) => size,
                _ => {
                    return Err(out_of_range(
                        JSON_STRUCTURE,
                        "segment size",
                        size,
                        "source size",
                        source_len,
                    ));
                }
            }
        }
    };
    if len == 0 {
        return Err(bad_field(JSON_STRUCTURE, "segment size", 0));
    }
    Ok(V2Segment {
        offset,
        len,
        sector_size,
        iv_tweak: opt_num(seg, "iv_tweak", 0)?,
        // dm-crypt without iv_large_sectors (what cryptsetup writes): the IV number counts
        // 512-byte units, so it steps by sector_size / 512 (checked against the 4096-byte-sector
        // fixture).
        iv_step: u64::from(sector_size / 512),
        cipher: text(seg, "encryption")?.to_owned(),
    })
}
