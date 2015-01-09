//! A minimal implementation of SHA1 for rust.
//!
//! Example:
//!
//! ```rust
//! extern crate sha1;
//! # fn main() {
//!
//! let mut m = sha1::Sha1::new();
//! m.update("Hello World!".as_bytes());
//! assert_eq!(m.hexdigest().as_slice(),
//!            "2ef7bde608ce5404e97d5f042f95f89f1c232871");
//! # }
//! ```

#![feature(slicing_syntax)]

#![experimental]

use std::io::{MemWriter, BufWriter};


/// Represents a Sha1 hash object in memory.
#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    data: Vec<u8>,
    len: u64,
}

const DEFAULT_STATE : [u32; 5] =
    [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];


fn to_hex(input: &[u8]) -> String {
    let mut s = String::new();
    for b in input.iter() {
        s.push_str(&format!("{:02x}", *b)[]);
    }
    return s;
}


impl Sha1 {

    /// Creates an fresh sha1 hash object.
    pub fn new() -> Sha1 {
        Sha1 {
            state: DEFAULT_STATE,
            data: Vec::new(),
            len: 0,
        }
    }

    fn process_block(&mut self, block: &[u8]) {
        assert_eq!(block.len(), 64);

        let mut words = [0u32; 80];
        for (i, chunk) in block.chunks(4).enumerate() {
            words[i] = (chunk[3] as u32) |
                       ((chunk[2] as u32) << 8) |
                       ((chunk[1] as u32) << 16) |
                       ((chunk[0] as u32) << 24);
        }

        fn ff(b: u32, c: u32, d: u32) -> u32 { d ^ (b & (c ^ d)) }
        fn gg(b: u32, c: u32, d: u32) -> u32 { b ^ c ^ d }
        fn hh(b: u32, c: u32, d: u32) -> u32 { (b & c) | (d & (b | c)) }
        fn ii(b: u32, c: u32, d: u32) -> u32 { b ^ c ^ d }

        fn left_rotate(x: u32, n: u32) -> u32 { (x << n as usize) | (x >> (32 - n) as usize) }

        for i in range(16us, 80) {
            let n = words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16];
            words[i] = left_rotate(n, 1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        for i in range(0us, 80) {
            let (f, k) = match i {
                0 ... 19 => (ff(b, c, d), 0x5a827999),
                20 ... 39 => (gg(b, c, d), 0x6ed9eba1),
                40 ... 59 => (hh(b, c, d), 0x8f1bbcdc),
                60 ... 79 => (ii(b, c, d), 0xca62c1d6),
                _ => (0, 0),
            };

            let tmp = left_rotate(a, 5) + f + e + k + words[i];
            e = d;
            d = c;
            c = left_rotate(b, 30);
            b = a;
            a = tmp;
        }

        self.state[0] += a;
        self.state[1] += b;
        self.state[2] += c;
        self.state[3] += d;
        self.state[4] += e;
    }

    /// Resets the hash object to it's initial state.
    pub fn reset(&mut self) {
        self.state = DEFAULT_STATE;
        self.data.clear();
        self.len = 0;
    }

    /// Update hash with input data.
    pub fn update(&mut self, data: &[u8]) {
        let mut d = self.data.clone();
        self.data.clear();

        d.push_all(data);

        for chunk in d[].chunks(64) {
            self.len += chunk.len() as u64;

            if chunk.len() == 64 {
                self.process_block(chunk);
            } else {
                self.data.push_all(chunk);
            }
        }
    }

    /// Retrieve digest result.  The output must be large enough to
    /// contain result (20 bytes).
    pub fn output(&self, out: &mut [u8]) {
        // these are unlikely to fail, since we're writing to memory
        #![allow(unused_must_use)]

        let mut m = Sha1 {
            state: self.state,
            data: Vec::new(),
            len: 0,
        };

        let mut w = MemWriter::new();
        w.write(&self.data[]);
        w.write_u8(0x80 as u8);
        let padding = (((56 - self.len as isize - 1) % 64) + 64) % 64;
        for _ in range(0, padding) {
            w.write_u8(0u8);
        }
        w.write_be_u64(self.len * 8);
        for chunk in w.get_ref()[].chunks(64) {
            m.process_block(chunk);
        }

        let mut w = BufWriter::new(out);
        for &n in m.state.iter() {
            w.write_be_u32(n);
        }
    }

    /// Shortcut for getting `output` into a new vector.
    pub fn digest(&self) -> Vec<u8> {
        let mut buf = [0u8; 20].to_vec();
        self.output(&mut *buf[]);
        buf
    }

    /// Shortcut for getting a hex output of the vector.
    pub fn hexdigest(&self) -> String {
        to_hex(self.digest()[])
    }
}


#[test]
fn test_simple() {
    let mut m = Sha1::new();

    let tests = [
        ("The quick brown fox jumps over the lazy dog",
         "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
        ("The quick brown fox jumps over the lazy cog",
         "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"),
        ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ("testing\n", "9801739daae44ec5293d4e1f53d3f4d2d426d91c"),
        ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
         "025ecbd5d70f8fb3c5457cd96bab13fda305dc59"),
    ];

    for &(s, ref h) in tests.iter() {
        let data = s.as_bytes();

        m.reset();
        m.update(data);
        let hh = m.hexdigest();

        assert_eq!(hh.len(), h.len());
        assert_eq!(hh[], *h);
    }
}
