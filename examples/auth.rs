use anyhow::Result;
use rand_core::{OsRng, RngCore};
use lioness_blockcipher::lioness::SEC_PARAM;
use lioness_blockcipher::prelude::*;

type TestLioness = Lioness::<
    ChaCha20StreamCipher,
    KeyedBlake2b,
    TurboShake128Kdf
>;

fn prepend_before_enc() -> Result<()>{
    let mut key: Key256 = Default::default();
    OsRng.fill_bytes(&mut key);
    let cipher: TestLioness = Lioness::new(&key)?;

    let payload = vec![0x84u8; 4096];
    let mut plaintext = vec![0u8; SEC_PARAM];
    plaintext.extend_from_slice(&payload);

    let mut block = plaintext.clone();
    cipher.encrypt_in_place(&mut block)?;

    // tamper with the ciphertext
    block[21] ^= 0x01;

    cipher.decrypt_in_place(&mut block)?;

    for b in block[..SEC_PARAM].iter(){
        if *b != 0{
            println!("tampering detected i.e. zero-prefix check failed");
            break
        }
    }

    Ok(())
}

fn call_enc_auth() -> Result<()>{
    let mut key: Key256 = Default::default();
    OsRng.fill_bytes(&mut key);
    let cipher: TestLioness = Lioness::new(&key)?;

    let mut payload = [0x84u8; 4096];

    // let mut block = plaintext.clone();
    let mut ciphertext = cipher.encrypt_auth(&mut payload)?;

    // tamper with the ciphertext
    ciphertext[21] ^= 0x01;

    assert!(cipher.decrypt_auth(&mut ciphertext).is_err());

    Ok(())
}

fn main() -> Result<()> {
    // prepend before calling the lioness encryption
    prepend_before_enc()?;
    // use built-in functions
    call_enc_auth()
}
