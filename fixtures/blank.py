# Shrinks a freshly made LUKS image so it packs small, without changing what is read:
#  1. cryptsetup fills every keyslot area with random bytes; the areas of inactive keyslots are
#     never read, so they are zeroed (the active keyslot's area and all headers stay as written);
#  2. the ciphertext of every 4 KiB block whose plaintext is all zeros is zeroed. Those blocks
#     decrypt to noise, which the tests never read (the filesystem has no journal).
# Usage: blank.py <image> <mapped device> <payload offset in bytes>
import json
import struct
import sys

img_path, dev_path, payload = sys.argv[1], sys.argv[2], int(sys.argv[3])
CHUNK = 4096
zero = bytes(CHUNK)


def blank_inactive_keyslots(img):
    img.seek(0)
    head = img.read(4096)
    version = struct.unpack(">H", head[6:8])[0]
    if version == 1:
        for i in range(8):
            base = 208 + 48 * i
            active, _iters = struct.unpack(">II", head[base : base + 8])
            if active == 0x00AC71F3:
                continue
            offset, _stripes = struct.unpack(">II", head[base + 40 : base + 48])
            key_bytes = struct.unpack(">I", head[108:112])[0]
            img.seek(offset * 512)
            img.write(bytes(key_bytes * 4000))
    else:
        hdr_size = struct.unpack(">Q", head[8:16])[0]
        img.seek(4096)
        meta = json.loads(img.read(hdr_size - 4096).split(b"\0")[0])
        first = 2 * hdr_size
        keep = [
            (int(s["area"]["offset"]), int(s["area"]["size"])) for s in meta["keyslots"].values()
        ]
        end = int(meta["segments"]["0"]["offset"])
        img.seek(first)
        img.write(bytes(end - first))
        for off, size in keep:
            pass
    return version


with open(img_path, "r+b") as img:
    # Keep the active keyslot data: read it before the LUKS2 wipe, write it back after.
    img.seek(0)
    head = img.read(4096)
    saved = []
    if struct.unpack(">H", head[6:8])[0] == 2:
        hdr_size = struct.unpack(">Q", head[8:16])[0]
        img.seek(4096)
        meta = json.loads(img.read(hdr_size - 4096).split(b"\0")[0])
        for s in meta["keyslots"].values():
            off, size = int(s["area"]["offset"]), int(s["area"]["size"])
            img.seek(off)
            saved.append((off, img.read(size)))
    blank_inactive_keyslots(img)
    for off, data in saved:
        img.seek(off)
        img.write(data)

    kept = blanked = 0
    with open(dev_path, "rb") as dev:
        pos = 0
        while True:
            plain = dev.read(CHUNK)
            if len(plain) < CHUNK:
                break
            if plain == zero:
                img.seek(payload + pos)
                img.write(zero)
                blanked += 1
            else:
                kept += 1
            pos += CHUNK
print(f"kept {kept} blocks, blanked {blanked}", file=sys.stderr)
