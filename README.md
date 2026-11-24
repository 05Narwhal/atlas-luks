# atlas-luks

Reads LUKS1 and LUKS2 volumes. `luks::open` parses the header, `Luks::unlock_source` finds the volume key from a password (PBKDF2 or Argon2 keyslots, with caps on the work a header may ask for) and returns a `BlockSource` that decrypts the payload sector by sector (AES-XTS, AES-CBC).

- `luks::mount(source, mounter)` gives one locked volume whose `unlock` decrypts the payload and passes it to a `Mounter` you supply, because this crate reads no filesystem itself.
- `kdf`, `xts` and `source` are public because `atlas-bitlocker` shares them.
- Secrets live in `Zeroizing` buffers; no key-holding type derives `Debug`.
- No `unsafe`. Every length, offset and count read from the disk is checked; damage is an error, not a panic.

## Licence

Licensed under either of Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or MIT license
([LICENSE-MIT](LICENSE-MIT)) at your option.
