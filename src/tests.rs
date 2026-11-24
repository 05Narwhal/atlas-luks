// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::luks::{self, Limits};
use super::source::{Decrypted, SectorCipher};
use super::test_image::{NAMES, PASSWORD, edit_v2, fix_checksum, load};
use super::xts::Xts;
use atlas_fs_core::error::Error;
use atlas_fs_core::fs::VolumeState;
use atlas_fs_core::io::block::{BlockSource, MemSource};

type Edit = Box<dyn Fn(&mut Value)>;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn mem(bytes: Vec<u8>) -> Arc<dyn BlockSource> {
    Arc::new(MemSource::new(bytes))
}

fn image(name: &str) -> Arc<dyn BlockSource> {
    mem(load(name).to_vec())
}

// ------------------------------------------------------------------ XTS

#[test]
fn xts_ieee_1619_vector_1() {
    // Vector 1 of IEEE 1619-2007: both keys zero, data unit 0, 32 zero bytes.
    let xts = Xts::new(&[0u8; 32]).unwrap();
    let ct = hex("917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e");
    let mut data = ct.clone();
    xts.decrypt_sector(0, &mut data);
    assert_eq!(data, vec![0u8; 32]);
    let mut again = vec![0u8; 32];
    xts.encrypt_with_tweak([0; 16], &mut again);
    assert_eq!(again, ct);
}

#[test]
fn xts_ieee_1619_vector_2() {
    // Vector 2: keys 11..11 and 22..22, data unit 0x3333333333, 32 bytes of 0x44.
    let mut key = vec![0x11u8; 16];
    key.extend([0x22u8; 16]);
    let xts = Xts::new(&key).unwrap();
    let ct = hex("c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0");
    let mut data = ct;
    xts.decrypt_sector(0x33_3333_3333, &mut data);
    assert_eq!(data, vec![0x44u8; 32]);
}

#[test]
fn xts_aes_256_with_a_large_unit_number() {
    // Made with the Python `cryptography` package (OpenSSL's XTS), 5 blocks.
    let key: Vec<u8> = (1..=64u32).map(|i| (i * 7 + 3) as u8).collect();
    let plain: Vec<u8> = (0..80u32).map(|i| (i * 13 + 5) as u8).collect();
    let ct = hex(
        "8df49841096ccde0f5ec043096ab98d08cc7efcc3498c10bf644238258a36e1be741784a29bf888af7e6b9d06530ef25653cccfb0bcf35e182d37ff88e26b407368e391f8e3156ca6e59fd456b6fc53c",
    );
    let xts = Xts::new(&key).unwrap();
    let mut data = ct;
    xts.decrypt_sector(0x0123_4567_89ab_cdef, &mut data);
    assert_eq!(data, plain);
}

#[test]
fn xts_rejects_odd_key_sizes() {
    for n in [0, 16, 24, 31, 33, 48, 63, 65, 128] {
        assert!(Xts::new(&vec![1u8; n]).is_none(), "{n}");
    }
}

#[test]
fn cipher_specs() {
    for (spec, key) in [
        ("aes-xts-plain64", 32),
        ("aes-xts-plain64", 64),
        ("aes-xts-plain", 64),
        ("aes-cbc-essiv:sha256", 16),
        ("aes-cbc-essiv:sha256", 32),
        ("aes-cbc-plain64", 32),
        ("aes-cbc-plain", 16),
    ] {
        let cipher = SectorCipher::parse(spec, &vec![7u8; key]).unwrap();
        let plain: Vec<u8> = (0..512u32).map(|i| i as u8).collect();
        let mut data = plain.clone();
        cipher.encrypt_sector(9, &mut data);
        assert_ne!(data, plain, "{spec}");
        cipher.decrypt_sector(9, &mut data);
        assert_eq!(data, plain, "{spec}");
    }
    for (spec, key) in [
        ("serpent-xts-plain64", 32),
        ("twofish-cbc-essiv:sha256", 32),
        ("aes-xts-essiv:sha256", 32),
        ("aes-cbc-essiv:sha512", 32),
        ("aes-lrw-benbi", 32),
        ("aes", 32),
        ("aes-xts-plain64", 20),
        ("aes-cbc-plain64", 64),
        ("", 32),
    ] {
        let Err(e) = SectorCipher::parse(spec, &vec![7u8; key]) else {
            panic!("{spec} / {key} parsed");
        };
        assert!(matches!(e, Error::Unsupported(_)), "{spec}: {e}");
    }
}

// --------------------------------------------------------- real images

#[test]
fn versions() {
    for (name, version) in NAMES.iter().zip([1u8, 1, 2, 2]) {
        assert_eq!(luks::open(image(name)).unwrap().version(), version);
    }
}

#[test]
fn the_decrypted_source_reads_any_range() {
    for name in NAMES {
        let luks = luks::open(image(name)).unwrap();
        let plain = luks.unlock_source(PASSWORD).unwrap();
        let sector = u64::from(plain.sector_size());
        assert_eq!(sector, if name == "luks2_argon2" { 4096 } else { 512 });
        let mut whole = vec![0u8; plain.len() as usize];
        plain.read_at(0, &mut whole).unwrap();
        // The ext4 superblock is at 1024 and has its magic at 56.
        assert_eq!(&whole[1024 + 56..1024 + 58], &[0x53, 0xEF], "{name}");
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200 {
            let offset = next() % plain.len();
            let len = (next() % 20_000).min(plain.len() - offset) as usize;
            let mut buf = vec![0u8; len];
            plain.read_at(offset, &mut buf).unwrap();
            assert_eq!(buf, whole[offset as usize..offset as usize + len], "{name}");
        }
        // Edges: one byte either side of a sector boundary, the very end, empty reads.
        for (offset, len) in [(sector - 1, 2usize), (0, 1), (plain.len() - 1, 1)] {
            let mut buf = vec![0u8; len];
            plain.read_at(offset, &mut buf).unwrap();
            assert_eq!(buf, whole[offset as usize..offset as usize + len]);
        }
        plain.read_at(plain.len(), &mut []).unwrap();
        let mut one = [0u8; 1];
        assert!(matches!(
            plain.read_at(plain.len(), &mut one),
            Err(Error::OutOfBounds { .. })
        ));
        assert!(matches!(
            plain.read_at(u64::MAX, &mut one),
            Err(Error::OutOfBounds { .. })
        ));
    }
}

#[test]
fn the_decrypted_source_checks_its_range() {
    let source = image("luks1_xts");
    let cipher = || SectorCipher::parse("aes-xts-plain64", &[1u8; 32]).unwrap();
    // Past the end, not a whole number of sectors, a sector size the format lacks.
    let size = source.len();
    assert!(Decrypted::new(source.clone(), cipher(), 4096, size, 512, 0, 1).is_err());
    assert!(Decrypted::new(source.clone(), cipher(), 0, 1000, 512, 0, 1).is_err());
    assert!(Decrypted::new(source.clone(), cipher(), u64::MAX, 512, 512, 0, 1).is_err());
    assert!(Decrypted::new(source.clone(), cipher(), 0, 1024, 100, 0, 1).is_err());
    assert!(Decrypted::new(source, cipher(), 0, 1024, 512, 0, 1).is_ok());
}

#[test]
fn a_primary_header_damaged_in_luks2_falls_back_to_the_secondary() {
    let mut bytes = load("luks2_pbkdf2").to_vec();
    // Break the checksum, then the JSON, of the primary.
    for at in [450usize, 4100, 4200] {
        let mut damaged = bytes.clone();
        damaged[at] ^= 0x40;
        let luks = luks::open(mem(damaged)).unwrap();
        luks.unlock_source(PASSWORD).unwrap();
    }
    // Both copies damaged: an error, not a volume.
    bytes[450] ^= 1;
    bytes[16384 + 450] ^= 1;
    assert!(matches!(luks::open(mem(bytes)), Err(Error::Corrupt(_))));
}

// ------------------------------------------------------------- hostile

fn open_err(bytes: Vec<u8>) -> Error {
    match luks::open(mem(bytes)) {
        Ok(_) => panic!("opened"),
        Err(e) => e,
    }
}

fn unlock_err(bytes: Vec<u8>) -> Error {
    match luks::open(mem(bytes)).and_then(|l| l.unlock_source(PASSWORD)) {
        Ok(_) => panic!("unlocked"),
        Err(e) => e,
    }
}

fn is_unsupported(e: &Error, needle: &str) -> bool {
    matches!(e, Error::Unsupported(text) if text.contains(needle))
}

#[test]
fn truncated_headers_fail_cleanly() {
    for name in NAMES {
        let full = load(name);
        for cut in [
            0usize, 1, 5, 6, 7, 8, 100, 591, 592, 593, 4095, 4096, 4097, 16383, 16384, 20000,
            100_000,
        ] {
            let Some(part) = full.get(..cut) else {
                continue;
            };
            // Never a panic. Where it opens, it must not unlock into a volume of zero length.
            if let Ok(src) = luks::open(mem(part.to_vec())).and_then(|l| l.unlock_source(PASSWORD))
            {
                assert!(!src.is_empty());
            }
        }
    }
}

#[test]
fn flipped_header_bytes_never_panic() {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let limits = Limits {
        pbkdf2_iterations: 5000,
        pbkdf2_total: 50_000,
        argon2_memory_kib: 2048,
        argon2_time: 8,
        argon2_cpus: 2,
        argon2_total: 100_000,
    };
    // The header: 592 bytes of LUKS1, the binary header and the JSON of LUKS2.
    for (name, span) in [
        ("luks1_xts", 592usize),
        ("luks1_cbc", 592),
        ("luks2_pbkdf2", 16384 + 4096),
    ] {
        let full = load(name);
        let mut opened = 0;
        for case in 0..70 {
            let mut bytes = full.to_vec();
            let at = (next() % span as u64) as usize;
            bytes[at] ^= 1 << (next() % 8);
            if case % 3 == 0 {
                // A second flip, in the keyslot area or the other copy.
                let at = (next() % span as u64) as usize;
                bytes[at] = (next() & 0xFF) as u8;
            }
            let Ok(l) = luks::open_with_limits(mem(bytes), limits) else {
                continue;
            };
            opened += 1;
            let _ = l.unlock_source(PASSWORD);
        }
        assert!(opened > 0, "{name}: no flipped header opened");
    }
    // The Argon2 image: flips in the metadata, with a small memory cap.
    let full = load("luks2_argon2");
    for _ in 0..25 {
        let mut bytes = full.to_vec();
        let at = (next() % 8192) as usize;
        bytes[at] ^= 1 << (next() % 8);
        if let Ok(l) = luks::open_with_limits(mem(bytes), limits) {
            let _ = l.unlock_source(PASSWORD);
        }
    }
}

#[test]
fn luks1_absurd_values_are_rejected() {
    let base = load("luks1_xts").to_vec();
    let patch = |at: usize, value: u32| {
        let mut b = base.clone();
        b[at..at + 4].copy_from_slice(&value.to_be_bytes());
        b
    };
    // Key bytes 0 and 129; slot stripes 0 and 4001; mk iterations 0.
    for bytes in [
        patch(108, 0),
        patch(108, 129),
        patch(108, u32::MAX),
        patch(208 + 44, 0),
        patch(208 + 44, 4001),
        patch(208 + 44, u32::MAX),
        patch(164, 0),
    ] {
        assert!(matches!(open_err(bytes), Error::Corrupt(_)));
    }
    // A keyslot area or a payload outside the source.
    assert!(matches!(
        open_err(patch(208 + 40, 1 << 30)),
        Error::Corrupt(_)
    ));
    assert!(matches!(open_err(patch(104, 1 << 30)), Error::Corrupt(_)));
    assert!(matches!(open_err(patch(104, u32::MAX)), Error::Corrupt(_)));
    // Iteration counts past the cap are refused before any work.
    let started = Instant::now();
    for bytes in [
        patch(208 + 4, u32::MAX),
        patch(208 + 4, 20_000_001),
        patch(164, u32::MAX),
    ] {
        let e = unlock_err(bytes);
        assert!(is_unsupported(&e, "too expensive"), "{e}");
    }
    assert!(started.elapsed() < Duration::from_secs(5));
    // A cipher or hash this reader lacks names itself.
    let mut b = base.clone();
    b[8..8 + 7].copy_from_slice(b"serpent");
    b[8 + 7] = 0;
    assert!(is_unsupported(&open_err(b), "serpent"));
    let mut b = base.clone();
    b[72..72 + 9].copy_from_slice(b"ripemd160");
    b[72 + 9] = 0;
    assert!(is_unsupported(&open_err(b), "ripemd160"));
    // No active keyslot.
    let mut b = base;
    b[208..212].copy_from_slice(&0xDEADu32.to_be_bytes());
    assert!(matches!(open_err(b), Error::Corrupt(_)));
}

fn json_edit_fails(name: &str, edit: impl Fn(&mut Value)) -> Error {
    open_err_or_unlock(edit_v2(load(name), edit))
}

/// The error from opening the image, or, when it opens, from unlocking it.
fn open_err_or_unlock(bytes: Vec<u8>) -> Error {
    match luks::open(mem(bytes)) {
        Err(e) => e,
        Ok(l) => match l.unlock_source(PASSWORD) {
            Err(e) => e,
            Ok(_) => panic!("unlocked"),
        },
    }
}

#[test]
fn luks2_absurd_metadata_is_rejected() {
    let started = Instant::now();
    // Costs past the caps: refused before any derivation.
    let too_expensive: Vec<(&str, Edit)> = vec![
        (
            "luks2_pbkdf2",
            Box::new(|v| v["keyslots"]["0"]["kdf"]["iterations"] = json!(4_000_000_000u64)),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["keyslots"]["0"]["kdf"]["iterations"] = json!(20_000_001u64)),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["digests"]["0"]["iterations"] = json!(u64::MAX)),
        ),
        (
            "luks2_argon2",
            Box::new(|v| v["keyslots"]["0"]["kdf"]["memory"] = json!(4_194_305u64)),
        ),
        (
            "luks2_argon2",
            Box::new(|v| v["keyslots"]["0"]["kdf"]["memory"] = json!(u64::MAX)),
        ),
        (
            "luks2_argon2",
            Box::new(|v| v["keyslots"]["0"]["kdf"]["time"] = json!(101)),
        ),
        (
            "luks2_argon2",
            Box::new(|v| v["keyslots"]["0"]["kdf"]["cpus"] = json!(65)),
        ),
    ];
    for (name, edit) in &too_expensive {
        let e = json_edit_fails(name, edit);
        assert!(is_unsupported(&e, "too expensive"), "{name}: {e}");
    }
    assert!(started.elapsed() < Duration::from_secs(5));

    // Counts and offsets the format does not allow.
    let corrupt: Vec<(&str, Edit)> = vec![
        (
            "luks2_pbkdf2",
            Box::new(|v| v["keyslots"]["0"]["af"]["stripes"] = json!(4001)),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["keyslots"]["0"]["af"]["stripes"] = json!(0)),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["keyslots"]["0"]["af"]["stripes"] = json!(u64::MAX)),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["keyslots"]["0"]["key_size"] = json!(129)),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["keyslots"]["0"]["key_size"] = json!(0)),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["keyslots"]["0"]["area"]["key_size"] = json!(4096)),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["keyslots"]["0"]["area"]["offset"] = json!("999999999999")),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["keyslots"]["0"]["area"]["offset"] = json!("18446744073709551615")),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["keyslots"]["0"]["area"]["size"] = json!("512")),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["keyslots"]["0"]["kdf"]["salt"] = json!("@@@@")),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["keyslots"]["0"]["kdf"]["salt"] = json!("")),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["keyslots"]["0"]["kdf"]["salt"] = json!("AAAA".repeat(2000))),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["segments"]["0"]["offset"] = json!("999999999999")),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["segments"]["0"]["size"] = json!("999999999999")),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["segments"]["0"]["size"] = json!("1000")),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["segments"]["0"]["sector_size"] = json!(100)),
        ),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["segments"]["0"]["sector_size"] = json!(65536)),
        ),
        ("luks2_pbkdf2", Box::new(|v| v["keyslots"] = json!([]))),
        ("luks2_pbkdf2", Box::new(|v| v["keyslots"] = json!({}))),
        ("luks2_pbkdf2", Box::new(|v| v["digests"] = json!({}))),
        ("luks2_pbkdf2", Box::new(|v| *v = json!([1, 2, 3]))),
        ("luks2_pbkdf2", Box::new(|v| *v = json!("text"))),
        ("luks2_pbkdf2", Box::new(|v| *v = json!({}))),
        (
            "luks2_pbkdf2",
            Box::new(|v| v["keyslots"]["0"]["type"] = json!("reencrypt")),
        ),
    ];
    for (name, edit) in &corrupt {
        let e = json_edit_fails(name, edit);
        assert!(matches!(e, Error::Corrupt(_)), "{name}: {e}");
    }

    // Features this reader does not have.
    let unsupported: Vec<(&str, &str, Edit)> = vec![
        (
            "reencryption",
            "re-encrypted",
            Box::new(|v| v["config"]["requirements"] = json!(["online-reencrypt-v2"])),
        ),
        (
            "second segment",
            "more than one",
            Box::new(|v| v["segments"]["1"] = v["segments"]["0"].clone()),
        ),
        (
            "linear segment",
            "linear",
            Box::new(|v| v["segments"]["0"]["type"] = json!("linear")),
        ),
        (
            "integrity",
            "integrity",
            Box::new(|v| {
                v["segments"]["0"]["integrity"] =
                    json!({"type": "hmac(sha256)", "journal_encryption": "none"})
            }),
        ),
        (
            "segment flags",
            "re-encrypted",
            Box::new(|v| v["segments"]["0"]["flags"] = json!(["in-reencryption"])),
        ),
        (
            "segment cipher",
            "serpent-xts-plain64",
            Box::new(|v| v["segments"]["0"]["encryption"] = json!("serpent-xts-plain64")),
        ),
        (
            "area cipher",
            "twofish-xts-plain64",
            Box::new(|v| v["keyslots"]["0"]["area"]["encryption"] = json!("twofish-xts-plain64")),
        ),
        (
            "kdf",
            "scrypt",
            Box::new(|v| v["keyslots"]["0"]["kdf"]["type"] = json!("scrypt")),
        ),
        (
            "af hash",
            "ripemd160",
            Box::new(|v| v["keyslots"]["0"]["af"]["hash"] = json!("ripemd160")),
        ),
        (
            "kdf hash",
            "whirlpool",
            Box::new(|v| v["keyslots"]["0"]["kdf"]["hash"] = json!("whirlpool")),
        ),
        (
            "digest type",
            "key digest",
            Box::new(|v| v["digests"]["0"]["type"] = json!("argon2")),
        ),
    ];
    for (what, needle, edit) in &unsupported {
        let e = json_edit_fails("luks2_pbkdf2", edit);
        assert!(is_unsupported(&e, needle), "{what}: {e}");
    }
}

#[test]
fn luks2_keyslots_without_a_digest_are_ignored() {
    // Keyslots no digest lists are dropped; the real one is still found.
    let bytes = edit_v2(load("luks2_pbkdf2"), |v| {
        for id in 1..16 {
            v["keyslots"][id.to_string()] = v["keyslots"]["0"].clone();
        }
    });
    let l = luks::open(mem(bytes)).unwrap();
    l.unlock_source(PASSWORD).unwrap();
}

#[test]
fn luks2_json_garbage_is_corrupt_not_a_crash() {
    let image = load("luks2_pbkdf2");
    let garbage = |fill: &dyn Fn(usize) -> Vec<u8>| {
        let mut out = image.to_vec();
        let hdr_size = 16384;
        for base in [0, hdr_size] {
            let json = fill(hdr_size - 4096);
            out[base + 4096..base + hdr_size].fill(0);
            out[base + 4096..base + 4096 + json.len()].copy_from_slice(&json);
            fix_checksum(&mut out[base..base + hdr_size]);
        }
        out
    };
    let cases: Vec<Vec<u8>> = vec![
        // Nesting far deeper than any real document.
        garbage(&|n| vec![b'['; n - 1]),
        garbage(&|n| {
            let mut v = b"{\"a\":".repeat((n - 1) / 5);
            v.truncate(n - 1);
            v
        }),
        // Not JSON at all, binary noise, empty, a lone brace.
        garbage(&|n| (0..n - 1).map(|i| (i * 37 % 255 + 1) as u8).collect()),
        garbage(&|_| Vec::new()),
        garbage(&|_| b"{".to_vec()),
        garbage(&|_| b"null".to_vec()),
        // Valid JSON of the wrong shapes.
        garbage(&|_| br#"{"keyslots":{"0":1},"digests":{},"segments":{}}"#.to_vec()),
        garbage(&|_| {
            br#"{"keyslots":{"0":{"type":"luks2"}},"digests":{"0":{}},"segments":{"0":{}}}"#
                .to_vec()
        }),
        // No terminating NUL: the area is all one document.
        garbage(&|n| {
            let mut v = vec![b' '; n];
            v[0] = b'{';
            v[n - 1] = b'}';
            v
        }),
    ];
    for bytes in cases {
        let e = open_err(bytes);
        assert!(matches!(e, Error::Corrupt(_)), "{e}");
    }
}

#[test]
fn headers_that_claim_a_size_they_do_not_have() {
    let image = load("luks2_pbkdf2");
    for size in [
        0u64,
        1,
        4096,
        16383,
        16385,
        1 << 22,
        1 << 23,
        u64::MAX,
        1 << 63,
    ] {
        let mut b = image.to_vec();
        for base in [0usize, 16384] {
            b[base + 8..base + 16].copy_from_slice(&size.to_be_bytes());
        }
        // The checksum is wrong, too; both reasons end in an error from every copy.
        assert!(matches!(open_err(b), Error::Corrupt(_)), "{size}");
    }
    // The header offset field must match where the header is.
    let mut b = image.to_vec();
    b[256..264].copy_from_slice(&1u64.to_be_bytes());
    fix_checksum(&mut b[..16384]);
    // The primary is refused, the secondary serves.
    luks::open(mem(b)).unwrap();
}

#[test]
fn argon2_memory_is_capped_by_the_limits() {
    let l = luks::open_with_limits(
        image("luks2_argon2"),
        Limits {
            argon2_memory_kib: 512,
            ..Limits::default()
        },
    )
    .unwrap();
    let e = l.unlock_source(PASSWORD).err().unwrap();
    assert!(is_unsupported(&e, "too expensive"), "{e}");
    let l = luks::open_with_limits(
        image("luks1_xts"),
        Limits {
            pbkdf2_total: 10,
            ..Limits::default()
        },
    )
    .unwrap();
    let e = l.unlock_source(PASSWORD).err().unwrap();
    assert!(is_unsupported(&e, "too expensive"), "{e}");
}

#[test]
fn argon2_work_is_capped_over_a_whole_unlock() {
    // One run is within the per-slot caps, but the unlock's total is not.
    let l = luks::open_with_limits(
        image("luks2_argon2"),
        Limits {
            argon2_total: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    let e = l.unlock_source(PASSWORD).err().unwrap();
    assert!(is_unsupported(&e, "too expensive"), "{e}");
}

#[test]
fn luks2_digest_longer_than_a_key_is_refused() {
    // 1024 bytes of digest would make PBKDF2 do up to 52 times the iterations.
    let e = json_edit_fails(
        "luks2_pbkdf2",
        &(Box::new(|v: &mut serde_json::Value| {
            v["digests"]["0"]["digest"] = json!(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [7u8; 1024]
            ))
        }) as Edit),
    );
    assert!(matches!(e, Error::Corrupt(_)), "{e}");
}

/// A mounter for tests that never unlock to a filesystem.
fn no_mounter(
    _: Arc<dyn BlockSource>,
) -> atlas_fs_core::error::Result<Arc<dyn atlas_fs_core::fs::FileSystem>> {
    Err(Error::unsupported("no mounter in this test"))
}

#[test]
fn a_source_that_fails_to_read_is_an_error_not_a_failed_volume() {
    struct Failing;
    impl BlockSource for Failing {
        fn len(&self) -> u64 {
            1 << 20
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> atlas_fs_core::error::Result<()> {
            Err(Error::io(
                atlas_fs_core::error::IoContext::Read {
                    offset,
                    len: buf.len() as u64,
                },
                std::io::Error::other("boom"),
            ))
        }
    }
    assert!(matches!(
        luks::mount(Arc::new(Failing), no_mounter),
        Err(Error::Io { .. })
    ));
    // A damaged header is a volume in the failed state.
    let volumes = luks::mount(mem(vec![0u8; 100_000]), no_mounter).unwrap();
    assert!(matches!(volumes[0].state, VolumeState::Failed(_)));
}

#[test]
fn compact_images_still_unlock() {
    for name in NAMES {
        let bytes = super::test_image::compact(name);
        assert!(bytes.len() <= 1 << 20, "{name}");
        let l = luks::open(mem(bytes)).unwrap();
        l.unlock_source(PASSWORD).unwrap();
        assert!(matches!(
            l.unlock_source("nope").err().unwrap(),
            Error::WrongPassword
        ));
    }
}
