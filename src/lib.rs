#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use cipher::consts::{U16, U32};
use cipher::generic_array::GenericArray;
use cipher::{AlgorithmName, BlockCipher, InvalidLength, KeyInit, KeySizeUser};
use core::fmt::Formatter;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod consts;
use crate::consts::{KEY_SCHEDULE, NUMBER_OF_ROUNDS};
use consts::S_BOX;

pub type UserKey = GenericArray<u8, U16>;

/// 1024-bit SEED key.
pub type Key = GenericArray<u32, U32>;

/// 128-bit SEED block.
pub type Block = GenericArray<u8, U16>;

enum TransformDirection {
    Encrypt,
    Decrypt,
}

pub struct SEED {
    key: Key,
}

fn derive_key(key: UserKey) -> Key {
    let (mut k0, mut k1, mut k2, mut k3) = divide_block(&key);
    let mut derived = Key::default();

    let mut temp;
    for i in 0..NUMBER_OF_ROUNDS {
        temp = k0.wrapping_add(k2).wrapping_sub(KEY_SCHEDULE[i]);
        derived[2 * i] = get_seed_substitute(temp);
        temp = k1.wrapping_sub(k3).wrapping_add(KEY_SCHEDULE[i]);
        derived[2 * i + 1] = get_seed_substitute(temp);

        if i % 2 == 0 {
            temp = (k1 >> 8) | (k0 << 24);
            k0 = (k0 >> 8) | (k1 << 24);
            k1 = temp;
        } else {
            temp = (k3 << 8) | (k2 >> 24);
            k2 = (k2 << 8) | (k3 >> 24);
            k3 = temp;
        }
    }

    derived
}

impl BlockCipher for SEED {}

impl KeySizeUser for SEED {
    type KeySize = U16;
}

impl KeyInit for SEED {
    fn new(key: &cipher::Key<Self>) -> Self {
        Self::new_from_slice(key).unwrap()
    }
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        if key.len() != 16 {
            return Err(InvalidLength);
        }

        Ok(SEED {
            key: derive_key(UserKey::clone_from_slice(key)),
        })
    }
}

#[cfg(feature = "zeroize")]
impl Drop for SEED {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for SEED {}

fn transform(
    l0: &mut u32,
    l1: &mut u32,
    r0: &mut u32,
    r1: &mut u32,
    key: Key,
    output: &mut Block,
    direction: TransformDirection,
) {
    match direction {
        TransformDirection::Encrypt => {
            for i in (0..=30).step_by(4) {
                seed_round(l0, l1, *r0, *r1, &key, i);
                seed_round(r0, r1, *l0, *l1, &key, i + 2);
            }
        }
        TransformDirection::Decrypt => {
            for i in (0..=30).rev().step_by(4) {
                seed_round(l0, l1, *r0, *r1, &key, i);
                seed_round(r0, r1, *l0, *l1, &key, i - 2);
            }
        }
    }

    let o = [r0, r1, l0, l1]
        .iter()
        .flat_map(|n| n.to_be_bytes())
        .collect::<Vec<u8>>();
    output[..].copy_from_slice(&o);
}

fn encrypt(block: Block, key: Key, output: &mut Block) {
    let (mut l0, mut l1, mut r0, mut r1) = divide_block(&block);
    transform(
        &mut l0,
        &mut l1,
        &mut r0,
        &mut r1,
        key,
        output,
        TransformDirection::Encrypt,
    );
}

fn decrypt(block: Block, key: Key, output: &mut Block) {
    let (mut l0, mut l1, mut r0, mut r1) = divide_block(&block);
    transform(
        &mut l0,
        &mut l1,
        &mut r0,
        &mut r1,
        key,
        output,
        TransformDirection::Decrypt,
    );
}

fn seed_round(l0: &mut u32, l1: &mut u32, r0: u32, r1: u32, key: &Key, offset: usize) {
    let k0 = key[offset];
    let k1 = key[offset + 1];

    let mut t0 = r0 ^ k0;
    let mut t1 = r1 ^ k1;
    t1 ^= t0;

    t1 = get_seed_substitute(t1);
    t0 = t0.wrapping_add(t1);
    t0 = get_seed_substitute(t0);
    t1 = t1.wrapping_add(t0);
    t1 = get_seed_substitute(t1);
    t0 = t0.wrapping_add(t1);
    *l0 ^= t0;
    *l1 ^= t1;
}

fn get_seed_substitute(value: u32) -> u32 {
    (0..4)
        .map(|idx| S_BOX[idx][((value >> (idx * 8)) as u8) as usize])
        .reduce(|acc, e| acc ^ e)
        .unwrap()
}

fn divide_block(block: &[u8]) -> (u32, u32, u32, u32) {
    assert_eq!(block.len(), 16);
    (
        u32::from_be_bytes(block[..4].try_into().unwrap()),
        u32::from_be_bytes(block[4..8].try_into().unwrap()),
        u32::from_be_bytes(block[8..12].try_into().unwrap()),
        u32::from_be_bytes(block[12..16].try_into().unwrap()),
    )
}

impl AlgorithmName for SEED {
    fn write_alg_name(f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("KISA-SEED")
    }
}

cipher::impl_simple_block_encdec!(
    SEED, U16, cipher, block,
    encrypt: {
        let mut b = block.clone_in();
        encrypt(b, cipher.key, &mut b);
        *block.get_out() = b;
    }
    decrypt: {
        let mut b = block.clone_in();
        decrypt(b, cipher.key, &mut b);
        *block.get_out() = b;
    }
);
