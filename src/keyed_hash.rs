use blake2::Blake2bMac;
use blake2::digest::{KeyInit as BlakeKeyInit, Mac, consts::U32};
use hmac::Hmac;
use sha2::{Sha256, Digest};
use crate::lioness::{Digest256, Key256, LionessKeyedHash};

//-----------------------keyed-blake2b-------------------------//
pub struct KeyedBlake2b;
impl LionessKeyedHash for KeyedBlake2b {
    fn hash(round_key: &Key256, input: &[u8]) -> anyhow::Result<Digest256> {
        let mut h = <Blake2bMac<U32> as BlakeKeyInit>::new_from_slice(round_key)?;
        Mac::update(&mut h, input);
        let mut digest: Digest256 = Default::default();
        digest.copy_from_slice(&h.finalize().into_bytes());
        Ok(digest)
    }
}

//----------------------------SHA256-PrependKey---------------------------------//
/// SHA256-PrependKey is here just SHA256 with the key prepended to the message, i.e. H(k || m)
/// Don't use this as MAC, should only be used in the context of LIONESS.
pub struct Sha256PrependKey;
impl LionessKeyedHash for Sha256PrependKey{
    fn hash(round_key: &Key256, input: &[u8]) -> anyhow::Result<Digest256> {
        let mut hash = Sha256::new();
        hash.update(round_key);
        hash.update(input);
        let output = hash.finalize();
        let mut digest: Digest256 = Default::default();
        digest.copy_from_slice(&output);
        Ok(digest)
    }
}

//----------------------------------HMAC-SHA-256--------------------------------------------//
pub struct HmacSha256KeyedHash;
type HmacSha256 = Hmac<Sha256>;
impl LionessKeyedHash for HmacSha256KeyedHash {
    fn hash(round_key: &Key256, input: &[u8]) -> anyhow::Result<Digest256> {
        let mut mac = HmacSha256::new_from_slice(round_key)?;
        mac.update(input);
        let result = mac.finalize().into_bytes();

        let mut digest: Digest256 = Default::default();
        digest.copy_from_slice(&result);
        Ok(digest)
    }
}
