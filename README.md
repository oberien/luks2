# luks2
Interact with (currently: read metadata and data from) LUKS2 partitions from Rust.

Build with `RUSTFLAGS="-C target-feature=+aes"` to use the AES processor instruction set (if
available on your platform).
