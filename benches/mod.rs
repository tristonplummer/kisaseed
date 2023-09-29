#![feature(test)]
extern crate test;

use cipher::{block_decryptor_bench, block_encryptor_bench};
use kisaseed::SEED;

block_encryptor_bench!(Key: SEED, seed_encrypt_block, seed_encrypt_blocks);
block_decryptor_bench!(Key: SEED, seed_decrypt_block, seed_decrypt_blocks);
