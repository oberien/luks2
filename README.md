# Fork of luks2

Original: https://sr.ht/~mvforell/luks2/

Interact with (currently: read metadata and data from) LUKS2 partitions from Rust.

Build with `RUSTFLAGS="-C target-feature=+aes"` to use the AES processor instruction set (if
available on your platform).

## Changes compared to original

* fix a bug where decryption fails due to an invalid iv when the sector_size is not 512
* add no_std support
* fix a bug where the final 16MB (segment-offset) of a segment weren't read
* fix a bug where the last sector wasn't read fully
* add `LuksHeader::uuid` function
* allow opening a `LuksDevice` with an existing `SecretMasterKey`
* fix a bug where decryption fails if keyslot and segmentslot aren't equal
* add sha1 support
