use anyhow::{Result, anyhow};
use blake2::Blake2bMac;
use blake2::digest::{KeyInit as BlakeKeyInit, Mac, consts::U32};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

// We expect the input key to be of size 32 bytes (128-bits)
// because in sphinx this is the size of the shared key `s` between the sender and each hop.
// This shared key is then used to derive all the needed keys to encrypt the payload
pub const MASTER_KEY_LEN: usize = 32;
// For LIONESS, the length of the left part of the key (after splitting block into left `L` and right `R`)
// must be the same size as:
// - the stream cipher key
// - the output (digest) of the keyed-hash function
// this is because:
// - in the stream cipher round you xor `L` with stream cipher key
// - in the hash round, you xor `L` with hash digest
pub const LEFT_LEN: usize = 32;
// ChaCha20 expects a key size of 32 bytes.
pub const STREAM_KEY_LEN: usize = 32;
// we use hash key of size 64. Rustcrypto blake2b accepts any key size
// but will pad to 64 anyway, 32 would also work
pub const HASH_KEY_LEN: usize = 64;

// we expect the block length `m` to be big
// it need to be bigger than the `left` length or stream cipher key size (these are equal)
// the paper states that |L| = k , and that |R| = m-k , so it implies that m > k
// there are probably ways to support small blocks, but for the sphinx case this would work.
pub const MIN_BLOCK_LEN: usize = LEFT_LEN + 1;
// the size of needed key material to output from the KDF,
// we need 2 steam keys and 2 hash keys
pub const KEY_MATERIAL_LEN: usize = 2 * STREAM_KEY_LEN + 2 * HASH_KEY_LEN;
// the master key supplied from user
pub type MasterKey = [u8; MASTER_KEY_LEN];

// chacha IV
const CHACHA20_IV: [u8; 12] = *b"chacha20_iv\0";

/// We need 4 keys, one for each round. Key sizes depend on if it is a cipher or hash round.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct RoundKeys {
    k1: [u8; STREAM_KEY_LEN],
    k2: [u8; HASH_KEY_LEN],
    k3: [u8; STREAM_KEY_LEN],
    k4: [u8; HASH_KEY_LEN],
}

/// LIONESS large-block cipher with:
/// - ChaCha20 stream cipher
/// - BLAKE2b keyed-hash (MAC) truncated to 32 bytes
/// - TurboSHAKE256 KDF for deriving sub-keys from a 32-byte "master" input key,
///
/// WARNING: integrity/authenticity is not guaranteed by the LIONESS large-block cipher
/// This is because LIONESS is not an AEAD but one can add an authentication check by
/// simply prepending the plaintext with `k` bytes of zeros
/// a safe value for `k` would be 32 bytes which is what the Sphinx paper suggests.
/// However, this prepending is not part of the code here.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Lioness {
    round_keys: RoundKeys,
}

impl Lioness {
    /// Create a new LIONESS instance from a 32-byte user supplied "master" key.
    pub fn new(master_key: &MasterKey) -> Self {
        Self {
            round_keys: derive_round_keys(master_key),
        }
    }

    /// Encrypt a single wide block in place. What it does is the following:
    /// - Split block `B` into left `L` and right `R` parts, `B` = `L|R` where `|L| = k` and `|R| = m-k`
    /// `m` is the message/plaintext size and `k` is the size of both streamcipher key and hash output
    /// - using `S` as the stream cipher, `K_i` as the round key, and `H` as the hash, apply the four rounds:
    /// 1. R = R ^ S(L ^ K_1)
    /// 2. L = L ^ H_{K_2}(R)
    /// 3. R = R ^ S(L ^ K_3)
    /// 4. L = L ^ H_{K_4}(R)
    pub fn encrypt_in_place(&self, block: &mut [u8]) -> Result<()> {
        if block.len() < MIN_BLOCK_LEN {
            return Err(anyhow!("block must be at least {} bytes", MIN_BLOCK_LEN));
        }
        // B = L|R
        let (left, right) = block.split_at_mut(LEFT_LEN);

        // R = R ^ S(L ^ K_1)
        stream_round(left, right, &self.round_keys.k1);
        // L = L ^ H_{K_2}(R)
        hash_round(left, right, &self.round_keys.k2)?;
        // R = R ^ S(L ^ K_3)
        stream_round(left, right, &self.round_keys.k3);
        // L = L ^ H_{K_4}(R)
        hash_round(left, right, &self.round_keys.k4)?;

        Ok(())
    }

    /// Decrypt a single wide block in place.
    /// Same as encryption but with the four steps flipped so from 4 -> 1
    pub fn decrypt_in_place(&self, block: &mut [u8]) -> Result<()> {
        if block.len() < MIN_BLOCK_LEN {
            return Err(anyhow!("blocks must be at least {} bytes", MIN_BLOCK_LEN));
        }
        // B = L|R
        let (left, right) = block.split_at_mut(LEFT_LEN);

        // L = L ^ H_{K_4}(R)
        hash_round(left, right, &self.round_keys.k4)?;
        // R = R ^ S(L ^ K_3)
        stream_round(left, right, &self.round_keys.k3);
        // L = L ^ H_{K_2}(R)
        hash_round(left, right, &self.round_keys.k2)?;
        // R = R ^ S(L ^ K_1)
        stream_round(left, right, &self.round_keys.k1);

        Ok(())
    }
}

/// derive all 4 keys from the master key using the KDF i.e. turboshake in here.
fn derive_round_keys(master_key: &MasterKey) -> RoundKeys {
    // WARNING: this uses the default domain separation 0x1f
    let mut kdf = Shake128::default();
    kdf.update(master_key);

    let mut reader = kdf.finalize_xof();
    let mut material = [0u8; KEY_MATERIAL_LEN];
    reader.read(&mut material);

    let mut k1 = [0u8; STREAM_KEY_LEN];
    let mut k2 = [0u8; HASH_KEY_LEN];
    let mut k3 = [0u8; STREAM_KEY_LEN];
    let mut k4 = [0u8; HASH_KEY_LEN];

    k1.copy_from_slice(&material[..STREAM_KEY_LEN]);
    k2.copy_from_slice(&material[STREAM_KEY_LEN..STREAM_KEY_LEN + HASH_KEY_LEN]);
    k3.copy_from_slice(&material[STREAM_KEY_LEN + HASH_KEY_LEN..2 * STREAM_KEY_LEN + HASH_KEY_LEN]);
    k4.copy_from_slice(&material[2 * STREAM_KEY_LEN + HASH_KEY_LEN..]);
    material.zeroize();

    RoundKeys { k1, k2, k3, k4 }
}

/// apply the steam cipher round
/// R = R ^ S(L ^ K_i)
fn stream_round(left: &[u8], right: &mut [u8], subkey: &[u8; STREAM_KEY_LEN]) {
    let mut round_key = [0u8; STREAM_KEY_LEN];
    // K = L ^ K_i
    xor(left, subkey, &mut round_key);
    // C = S(L ^ K)
    let mut cipher = ChaCha20::new(&round_key.into(), &CHACHA20_IV.into());
    // R = R ^ C
    cipher.apply_keystream(right);
    round_key.zeroize();
}

/// apply the hash round
/// L = L ^ H_{K_i}(R)
fn hash_round(left: &mut [u8], right: &[u8], subkey: &[u8; HASH_KEY_LEN]) -> Result<()> {
    let mut h = <Blake2bMac<U32> as BlakeKeyInit>::new_from_slice(subkey)?;
    Mac::update(&mut h, right);

    let mut digest = [0u8; LEFT_LEN];
    // D = H_{K_i}(R)
    digest.copy_from_slice(&h.finalize().into_bytes());
    // L = L ^ D
    xor_in_place(left, &digest);
    digest.zeroize();

    Ok(())
}

fn xor(left: &[u8], right: &[u8], out: &mut [u8]) {
    assert_eq!(left.len(), right.len());
    assert_eq!(left.len(), out.len());

    for ((dst, lhs), rhs) in out.iter_mut().zip(left.iter()).zip(right.iter()) {
        *dst = *lhs ^ *rhs;
    }
}

fn xor_in_place(bufer: &mut [u8], mask: &[u8]) {
    assert_eq!(bufer.len(), mask.len());

    for (dest, src) in bufer.iter_mut().zip(mask.iter()) {
        *dest ^= *src;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_test_key() -> MasterKey {
        let mut key = [0u8; MASTER_KEY_LEN];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8;
        }
        key
    }

    #[test]
    fn rejects_short_blocks() {
        let cipher = Lioness::new(&get_test_key());
        let mut block = [0u8; LEFT_LEN];

        assert!(cipher.encrypt_in_place(&mut block).is_err());
    }

    #[test]
    fn enc_dec_round_trip() {
        let cipher = Lioness::new(&get_test_key());
        let mut block = vec![0x84u8; 4096];

        let original = block.clone();
        cipher.encrypt_in_place(&mut block).unwrap();
        assert_ne!(block, original);

        cipher.decrypt_in_place(&mut block).unwrap();
        assert_eq!(block, original);
    }

    #[test]
    fn same_input_same_key() {
        let key = get_test_key();
        let cipher_a = Lioness::new(&key);
        let cipher_b = Lioness::new(&key);
        let mut outa = vec![0x42u8; 512];
        let mut outb = outa.clone();

        cipher_a.encrypt_in_place(&mut outa).unwrap();
        cipher_b.encrypt_in_place(&mut outb).unwrap();
        assert_eq!(outa, outb);
    }
}
