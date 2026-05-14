use rand_core::{OsRng, RngCore};
use lioness_blockcipher::cipher::Aes128CtrStreamCipher;
use lioness_blockcipher::kdf::DomSepSha256Kdf;
use lioness_blockcipher::keyed_hash::Sha256PrependKey;
use lioness_blockcipher::prelude::*;
type TestLioness = Lioness::<
    Aes128CtrStreamCipher,
    Sha256PrependKey,
    DomSepSha256Kdf,
>;

fn main() -> anyhow::Result<()> {
    let mut key: Key256 = Default::default();
    OsRng.fill_bytes(&mut key);

    let cipher: TestLioness = Lioness::new(&key)?;

    // Blocks must be at >64 bytes long
    let mut block = vec![0x84u8; 65];
    let original = block.clone();

    cipher.encrypt_in_place(&mut block)?;

    cipher.decrypt_in_place(&mut block)?;

    assert_eq!(block, original);
    println!("success!");

    Ok(())
}
