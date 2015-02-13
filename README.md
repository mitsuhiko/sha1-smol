# rust-sha1-hasher <a href="https://travis-ci.org/kstep/rust-sha1-hasher"><img src="https://img.shields.io/travis/kstep/rust-sha1-hasher.png?style=flat-square" /></a> <a href="https://crates.io/crates/sha1-hasher"><img src="https://img.shields.io/crates/d/sha1-hasher.png?style=flat-square" /></a> <a href="https://crates.io/crates/sha1-hasher"><img src="https://img.shields.io/crates/v/sha1-hasher.png?style=flat-square" /></a>

Minimal implementation of SHA1 for Rust. This might go away in the future
if rust-crypto or some libraries like that split into smaller parts.

Right now SHA1 is quite frequently used and many things want to have an
implementation of it, that does not pull in too much other stuff.

This is largely based on the hash code in crypto-rs by Koka El Kiwi.

This fork also adds some fixes for long data hashing (original version
has bug with hashing data built with several `update()` calls)
and reimplements functionality using `Hash` and `Hasher` traits
from Rust's standard lib, making it more composable.
