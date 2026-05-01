use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use crate::lioness::{Key256, LionessCipher};

// ---------------- chacha20 ------------------ //
// chacha IV
const CHACHA20_IV: [u8; 12] = *b"chacha20_iv\0";
pub struct ChaCha20StreamCipher;
impl LionessCipher for ChaCha20StreamCipher{
    fn apply_keystream(round_key: &Key256, block: &mut [u8]) -> anyhow::Result<()> {
        let mut cipher = ChaCha20::new(&(*round_key).into(), &CHACHA20_IV.into());
        cipher.apply_keystream(block);
        Ok(())
    }
}

//----------------------AES-CTR-128--------------------------//

pub struct Aes128CtrStreamCipher;
type Aes128CtrBE = ctr::Ctr128BE<aes::Aes128>;
impl LionessCipher for Aes128CtrStreamCipher{
    fn apply_keystream(round_key: &Key256, block: &mut [u8]) -> anyhow::Result<()> {
        let (aes_key, aes_iv) = round_key.split_at(16);
        let mut cipher = Aes128CtrBE::new_from_slices(aes_key, aes_iv)?;
        cipher.apply_keystream(block);
        Ok(())
    }
}