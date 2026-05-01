use std::marker::PhantomData;
use anyhow::{Result, anyhow};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// security parameter used. This is set to 16-bytes (128-bits) to match the Mix protocol.
pub const SEC_PARAM: usize = 16;

/// k, which we set here to 32-bytes (256-bits), is a constant size that will be used for many params:
/// - the length of the left part (after splitting block into left `L` and right `R`)
/// - the stream cipher key size
/// - the keyed-hash key size
/// - the output (digest) size of the keyed-hash function
/// - the internal LIONESS round key size
pub const K_256: usize = 2*SEC_PARAM;

/// 32 bytes (256-bit) key type
pub type Key256 = [u8; K_256];
/// digest type of size 32-bytes (256-bit).
/// We require the keyed hash to output a digest of the same size as Key256
pub type Digest256 = Key256;

/// We need 4 keys, one for each round. We use 256-byte keys for both cipher and keyed hash.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RoundKeys {
    pub keys: [Key256; 4],
}

impl Default for RoundKeys {
    fn default() -> Self{
        Self{
            keys: Default::default()
        }
    }
}

impl RoundKeys {
    pub fn from_key_material(key_material: &[u8; 4*K_256]) -> Self{
        let mut keys: [Key256; 4] = Default::default();
        for (ki, km) in keys.iter_mut().zip(key_material.chunks_exact(K_256)){
            ki.copy_from_slice(km);
        }
        Self{
            keys
        }
    }
}

/// LIONESS KDF trait, require a function which take a master key and generates 4 round keys each of size `K_256`
pub trait LionessKdf{
    fn derive_keys(master_key: &Key256) -> Result<RoundKeys>;
}

/// LIONESS stream cipher trait, the cipher takes a round key of size `K_256`, a block of data of any size
/// the function `apply_keystream` will generate a key stream (using the round key) and apply that keystream to the block.
pub trait LionessCipher{
    fn apply_keystream(round_key: &Key256, block: &mut [u8]) -> Result<()>;
}

/// LIONESS keyed hash trait, the hash takes a key (round key) and input of any size
/// outputs a hash digest with size equals to `K_256`
pub trait LionessKeyedHash{
    fn hash(round_key: &Key256, input: &[u8]) -> Result<Digest256>;
}

/// LIONESS large-block cipher with:
/// - S: stream cipher
/// - H: keyed-hash (MAC) truncated to 32 bytes
/// - K: KDF for deriving sub-keys from a 32-byte "masterkey",
#[derive(Clone, ZeroizeOnDrop)]
pub struct Lioness<S, H, K> {
    round_keys: RoundKeys,
    #[zeroize(skip)]
    phantom_data: PhantomData<(S,H,K)>
}

impl<
    S: LionessCipher,
    H: LionessKeyedHash,
    K: LionessKdf
> Lioness<S, H, K> {
    /// Create a new LIONESS instance from a 32-byte user supplied "master key".
    /// We expect the input "masterkey" to be of size 32 bytes.
    /// because in sphinx this is the size of the shared key `s` between the sender and each hop.
    /// This shared key is then used to derive all the needed keys to encrypt the payload
    pub fn new(master_key: &Key256) -> Result<Self> {
        Ok(
            Self {
                round_keys: K::derive_keys(master_key)?,
                phantom_data: Default::default(),
            }
        )
    }

    /// Encrypt a single wide block in place. What it does is the following:
    /// - Split block `B` into left `L` and right `R` parts, `B` = `L|R` where `|L| = k` and `|R| = m-k`
    /// `block` is the message/plaintext size
    /// - using `S` as the stream cipher, `K_i` as the round key, and `H` as the keyed hash, apply the four rounds:
    /// 1. R = R ^ S(L ^ K_1)
    /// 2. L = L ^ H_{K_2}(R)
    /// 3. R = R ^ S(L ^ K_3)
    /// 4. L = L ^ H_{K_4}(R)
    /// WARNING: for encryption with integrity/authenticity use `encrypt_in_place_auth`
    pub fn encrypt_in_place(&self, block: &mut [u8]) -> Result<()> {
        // we expect the block length `m` to be big, so we expect at least `2*K_256`
        if block.len() < 2*K_256 {
            return Err(anyhow!("block must be at least {} bytes", 2*K_256));
        }
        // B = L|R
        let (left, right) = block.split_at_mut(K_256);

        // R = R ^ S(L ^ K_1)
        self.stream_round(left, right, &self.round_keys.keys[0])?;
        // L = L ^ H_{K_2}(R)
        self.hash_round(left, right, &self.round_keys.keys[1])?;
        // R = R ^ S(L ^ K_3)
        self.stream_round(left, right, &self.round_keys.keys[2])?;
        // L = L ^ H_{K_4}(R)
        self.hash_round(left, right, &self.round_keys.keys[3])?;

        Ok(())
    }

    /// Same as `encrypt_in_place` but prepends the plaintext with `SEC_PARAM` bytes of zeros
    pub fn encrypt_in_place_auth(&self, _block: &mut [u8]) -> Result<()> {
        let mut plaintext = vec![0u8; SEC_PARAM];
        plaintext.extend_from_slice(_block);
        todo!()
    }

    /// Decrypt a single wide block in place.
    /// Same as encryption but with the four steps flipped so from 4 -> 1
    /// WARNING: for decryption with integrity/authenticity use `decrypt_in_place_auth`
    pub fn decrypt_in_place(&self, block: &mut [u8]) -> Result<()> {
        if block.len() < 2*K_256 {
            return Err(anyhow!("blocks must be at least {} bytes", 2*K_256));
        }
        // B = L|R
        let (left, right) = block.split_at_mut(K_256);

        // L = L ^ H_{K_4}(R)
        self.hash_round(left, right, &self.round_keys.keys[3])?;
        // R = R ^ S(L ^ K_3)
        self.stream_round(left, right, &self.round_keys.keys[2])?;
        // L = L ^ H_{K_2}(R)
        self.hash_round(left, right, &self.round_keys.keys[1])?;
        // R = R ^ S(L ^ K_1)
        self.stream_round(left, right, &self.round_keys.keys[0])?;

        Ok(())
    }

    /// Same as `decrypt_in_place` with added check for `SEC_PARAM`-bytes zero prefix
    pub fn decrypt_in_place_auth(&self, _block: &mut [u8]) -> Result<()> {
        todo!()
    }

    /// apply the steam cipher round
    /// R = R ^ S(L ^ K_i)
    fn stream_round(&self, left: &[u8], right: &mut [u8], subkey: &Key256) -> Result<()>{
        let mut round_key: Key256 = [0u8; K_256];
        // K = L ^ K_i
        xor(left, subkey, &mut round_key);
        // generate key stream: KS = S(L ^ K)
        // and apply the key stream R = R ^ KS
        S::apply_keystream(&round_key, right)?;
        round_key.zeroize();
        Ok(())
    }

    /// apply the hash round
    /// L = L ^ H_{K_i}(R)
    fn hash_round(&self, left: &mut [u8], right: &[u8], round_key: &Key256) -> Result<()> {
        // h = H_{K_i}(R)
        let mut digest= H::hash(round_key, right)?;
        // L = L ^ h
        xor_in_place(left, &digest);
        digest.zeroize();

        Ok(())
    }
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

