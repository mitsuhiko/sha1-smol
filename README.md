# sha1-smol

Minimal and dependency free implementation of SHA1 for Rust.

SHA1 is not exactly a good choice for crypto hashes these days but unfortunately
SHA1 continues to be needed for a handful of situations due to legacy functionality.
If you have the need for a SHA1 implementation that does not pull in large dependency chains
you might want to consider this crate.

In all other cases use the new [`sha1`](https://crates.io/crates/sha1) crate
by the RustCrypto project instead.

## sha1 crate

This crate used to be published as `sha1` but in recent years a large ecosystem
of hash libraries was built around [`RustCrypto`](https://github.com/RustCrypto)
so the crate name was given to that project instead.  Versions newer than `0.6`
of `sha1`.

This is largely based on the hash code in crypto-rs by Koka El Kiwi.
