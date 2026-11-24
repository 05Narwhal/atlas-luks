// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! The LUKS images the tests read. `fixtures/make_fixtures.sh` makes them with
//! `cryptsetup luksFormat` (password `atlas-test`) around a small ext4 volume;
//! `blank.py` zeroes what is never read and `pack.py` keeps the non-zero runs,
//! zstd compressed. Loading one gives the whole image in memory.

use std::sync::OnceLock;

use serde_json::Value;

use super::kdf::{Hash, digest_into};

/// The password every fixture opens with.
pub const PASSWORD: &str = "atlas-test";

/// What `/hello.txt` holds in every fixture.
pub const HELLO: &[u8] = b"Hello from an encrypted volume, read by Disk Atlas.\n";

/// The fixtures: LUKS1 AES-XTS (sha256), LUKS1 AES-CBC-ESSIV (sha1), LUKS2
/// PBKDF2 with 512-byte sectors, LUKS2 Argon2id with 4096-byte sectors.
pub const NAMES: [&str; 4] = ["luks1_xts", "luks1_cbc", "luks2_pbkdf2", "luks2_argon2"];

fn unpack(compressed: &[u8]) -> Vec<u8> {
    let pack = zstd::stream::decode_all(compressed).expect("decompress the fixture");
    let len = usize::try_from(u64::from_le_bytes(pack[..8].try_into().unwrap())).unwrap();
    let mut image = vec![0u8; len];
    let mut at = 8;
    while at < pack.len() {
        let offset = u64::from_le_bytes(pack[at..at + 8].try_into().unwrap()) as usize;
        let n = u32::from_le_bytes(pack[at + 8..at + 12].try_into().unwrap()) as usize;
        image[offset..offset + n].copy_from_slice(&pack[at + 12..at + 12 + n]);
        at += 12 + n;
    }
    image
}

/// The image of the fixture `name` (one of [`NAMES`]).
pub fn load(name: &str) -> &'static [u8] {
    static CACHE: [OnceLock<Vec<u8>>; 4] = [
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
    ];
    let index = NAMES
        .iter()
        .position(|n| *n == name)
        .expect("a fixture name");
    CACHE[index].get_or_init(|| match index {
        0 => unpack(include_bytes!("../fixtures/luks1_xts.pack.zst")),
        1 => unpack(include_bytes!("../fixtures/luks1_cbc.pack.zst")),
        2 => unpack(include_bytes!("../fixtures/luks2_pbkdf2.pack.zst")),
        _ => unpack(include_bytes!("../fixtures/luks2_argon2.pack.zst")),
    })
}

/// LUKS2 image with its JSON area changed by `edit`, in both header copies,
/// with the checksums made right again.
pub fn edit_v2(image: &[u8], edit: impl Fn(&mut Value)) -> Vec<u8> {
    let mut out = image.to_vec();
    let hdr_size = u64::from_be_bytes(out[8..16].try_into().unwrap()) as usize;
    for base in [0, hdr_size] {
        let json_at = base + 4096;
        let json_end = base + hdr_size;
        let area = &out[json_at..json_end];
        let len = area.iter().position(|&b| b == 0).unwrap_or(area.len());
        let mut value: Value = serde_json::from_slice(&area[..len]).unwrap();
        edit(&mut value);
        let text = serde_json::to_vec(&value).unwrap();
        assert!(text.len() < json_end - json_at, "edited JSON does not fit");
        out[json_at..json_end].fill(0);
        out[json_at..json_at + text.len()].copy_from_slice(&text);
        fix_checksum(&mut out[base..base + hdr_size]);
    }
    out
}

/// Recomputes the sha256 checksum of the LUKS2 header copy `header`.
pub fn fix_checksum(header: &mut [u8]) {
    header[448..512].fill(0);
    let mut sum = [0u8; 32];
    digest_into(Hash::Sha256, header, &mut sum);
    header[448..480].copy_from_slice(&sum);
}

/// A copy of a LUKS image that fits the fuzz run's 1 MiB input limit: the
/// header and key material are kept, the payload offset is moved down to the
/// end of the keyslot area (so the payload is whatever follows, undecryptable
/// noise) and the image is cut to 1 MiB.
pub fn compact(name: &str) -> Vec<u8> {
    let image = load(name);
    let mut out = if name.starts_with("luks1") {
        let mut v = image[..1 << 20].to_vec();
        // Key material of slot 0 ends before sector 512; payload offset in sectors.
        v[104..108].copy_from_slice(&600u32.to_be_bytes());
        v
    } else {
        let end = if name == "luks2_pbkdf2" {
            557_056
        } else {
            294_912
        };
        let mut v = edit_v2(image, |json| {
            json["segments"]["0"]["offset"] = Value::String(end.to_string());
        });
        v.truncate(1 << 20);
        v
    };
    out.shrink_to_fit();
    out
}
