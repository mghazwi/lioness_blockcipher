use sha2::{Sha256, Digest};
use turboshake::TurboShake128;
use turboshake::digest::{Update, ExtendableOutput, XofReader};
use sha3::Shake128;
use hkdf::Hkdf;
use zeroize::Zeroize;
use crate::lioness::{K_256, Key256, LionessKdf};
use crate::lioness::RoundKeys;

const KEY_MATERIAL_SIZE: usize = 4 * K_256;
const LIONESS_KDF_DOMAIN: &[u8] = b"lioness-payload-key";

//-----------------------turboshake128-------------------------//
pub struct TurboShake128Kdf;
impl LionessKdf for TurboShake128Kdf{
    fn derive_keys(master_key: &Key256) -> anyhow::Result<RoundKeys> {
        // NOTE: this uses the default domain separation 0x1f
        let mut kdf = <TurboShake128>::default();
        kdf.update(LIONESS_KDF_DOMAIN);
        kdf.update(master_key);
        let mut reader = kdf.finalize_xof();
        let mut material = [0u8; KEY_MATERIAL_SIZE];
        reader.read(&mut material);
        let round_keys = RoundKeys::from_key_material(&material);
        material.zeroize();
        Ok(round_keys)
    }
}

//--------------------------SHAKE-128------------------------------//
pub struct Shake128Kdf;
impl LionessKdf for Shake128Kdf {
    fn derive_keys(master_key: &Key256) -> anyhow::Result<RoundKeys> {
        let mut kdf = Shake128::default();
        kdf.update(LIONESS_KDF_DOMAIN);
        kdf.update(master_key);
        let mut reader = kdf.finalize_xof();
        let mut material = [0u8; KEY_MATERIAL_SIZE];
        reader.read(&mut material);
        let round_keys = RoundKeys::from_key_material(&material);
        material.zeroize();
        Ok(round_keys)
    }
}

//-----------------------------HKDF-SHA256----------------------------------//
pub struct HkdfSha256;
impl LionessKdf for HkdfSha256{
    fn derive_keys(master_key: &Key256) -> anyhow::Result<RoundKeys> {
        let kdf = Hkdf::<Sha256>::new(None, master_key);
        let mut material = [0u8; KEY_MATERIAL_SIZE];
        kdf.expand(LIONESS_KDF_DOMAIN, &mut material)?;
        let round_keys = RoundKeys::from_key_material(&material);
        material.zeroize();
        Ok(round_keys)
    }
}

//---------------------------------dom-sep-sha256----------------------------------------//

pub struct DomSepSha256Kdf;
const LIONESS_ROUND_KEY_DOMAINS: [&[u8]; 4] = [
    b"lioness-key1",
    b"lioness-key2",
    b"lioness-key3",
    b"lionesskey4",
];
impl LionessKdf for DomSepSha256Kdf {
    fn derive_keys(master_key: &Key256) -> anyhow::Result<RoundKeys> {
        let mut round_keys: RoundKeys = Default::default();
        for (i, key) in round_keys.keys.iter_mut().enumerate() {
            let mut hash = Sha256::new();
            Digest::update(&mut hash, LIONESS_KDF_DOMAIN);
            Digest::update(& mut hash, LIONESS_ROUND_KEY_DOMAINS[i]);
            Digest::update(& mut hash, master_key);
            Digest::update(& mut hash, master_key);
            let output = hash.finalize();
            key.copy_from_slice(&output);

        }
        Ok(round_keys)
    }
}