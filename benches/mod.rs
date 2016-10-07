#![no_std]
#![feature(test)]
extern crate test;
extern crate sha1;

use test::Bencher;
use sha1::{Sha1, sha1_digest_block_u32, Digest};

// Copied from src/lib.rs
const STATE_LEN: usize = 5;
const BLOCK_LEN: usize = 16;

#[bench]
pub fn sha1_block(bh: &mut Bencher) {
    let mut state = [0u32; STATE_LEN];
    let words = [1u32; BLOCK_LEN];
    bh.iter(|| {
        sha1_digest_block_u32(&mut state, &words);
    });
    bh.bytes = 64u64;
}

#[bench]
pub fn sha1_10(bh: &mut Bencher) {
    let mut sh = Sha1::new();
    let bytes = [1u8; 10];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha1_1k(bh: &mut Bencher) {
    let mut sh = Sha1::new();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha1_64k(bh: &mut Bencher) {
    let mut sh = Sha1::new();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}
