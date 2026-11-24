#!/bin/sh
# Rebuilds the LUKS fixtures with cryptsetup. Needs root, cryptsetup 2.x, python3, zstd, e2fsprogs
# and a kernel with dm-crypt and loop devices (WSL2 has them):
#   wsl.exe -d kali-linux -u root -- sh make_fixtures.sh <out dir>
# Every image is a real `cryptsetup luksFormat` result with the password "atlas-test", holding a
# small ext4 volume (no journal) with /hello.txt and /sub/nested.txt. After the filesystem is
# written, the ciphertext of all-zero plaintext blocks is zeroed (blank.py) and the image is stored
# as its non-zero runs (pack.py) and zstd compressed. Cheap key derivation so debug builds unlock
# in a second or two.
#   luks1_xts      LUKS1, aes-xts-plain64, 256-bit key, sha256
#   luks1_cbc      LUKS1, aes-cbc-essiv:sha256, 128-bit key, sha1
#   luks2_pbkdf2   LUKS2, aes-xts-plain64, 512-bit key, pbkdf2 sha256, 512-byte sectors
#   luks2_argon2   LUKS2, aes-xts-plain64, 256-bit key, argon2id, 4096-byte sectors
set -e
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$here}
work=$(mktemp -d)
pw=atlas-test
modprobe dm_crypt 2>/dev/null || true
for stale in luks1_xts luks1_cbc luks2_pbkdf2 luks2_argon2; do
    cryptsetup close "atlas-$stale" 2>/dev/null || true
done

# name, image size, ext4 block size, luksFormat arguments...
make() {
    name=$1; size=$2; bs=$3; shift 3
    img="$work/$name.img"
    truncate -s "$size" "$img"
    printf %s "$pw" | cryptsetup luksFormat --batch-mode "$@" "$img" -
    printf %s "$pw" | cryptsetup open "$img" "atlas-$name" -
    dev="/dev/mapper/atlas-$name"
    # A fresh image decrypts to noise: write zeros through the mapping so unused blocks read as zero.
    dd if=/dev/zero of="$dev" bs=1M status=none 2>/dev/null || true
    mkdir -p "$work/tree/sub"
    printf 'Hello from an encrypted volume, read by Disk Atlas.\n' > "$work/tree/hello.txt"
    printf 'nested file\n' > "$work/tree/sub/nested.txt"
    mkfs.ext4 -q -b "$bs" -O ^has_journal -E lazy_itable_init=0,nodiscard -N 16 -L atlas-luks -d "$work/tree" "$dev"
    sync
    # The offset of the data in the image, in 512-byte sectors, is the last field of the table.
    sectors=$(dmsetup table "$dev" | awk '{print $8}')
    python3 "$here/blank.py" "$img" "$dev" $((sectors * 512))
    cryptsetup close "atlas-$name"
    python3 "$here/pack.py" "$img" "$work/$name.pack"
    zstd -19 --long=27 -q -f "$work/$name.pack" -o "$out/$name.pack.zst"
    rm -rf "$work/tree"
}

make luks1_xts 3m 1024 --type luks1 --cipher aes-xts-plain64 --key-size 256 --hash sha256 \
    --pbkdf-force-iterations 1000
make luks1_cbc 3m 1024 --type luks1 --cipher aes-cbc-essiv:sha256 --key-size 128 --hash sha1 \
    --pbkdf-force-iterations 1000
make luks2_pbkdf2 4m 1024 --type luks2 --cipher aes-xts-plain64 --key-size 512 --hash sha256 \
    --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --sector-size 512 --luks2-metadata-size 16k --luks2-keyslots-size 512k
make luks2_argon2 4m 4096 --type luks2 --cipher aes-xts-plain64 --key-size 256 --hash sha256 \
    --pbkdf argon2id --pbkdf-memory 1024 --pbkdf-parallel 1 --pbkdf-force-iterations 4 \
    --sector-size 4096 --luks2-metadata-size 16k --luks2-keyslots-size 256k
[ -n "$KEEP" ] || rm -rf "$work"; echo "$work"
