use anyhow::Result;
use lioness_blockcipher::{Lioness, MasterKey};

const K: usize = 16;

fn main() -> Result<()> {
    let key: MasterKey = [0x42; 32];
    let cipher = Lioness::new(&key);

    let payload = b"this plaintext msg is prefixed with k zeros before encryption";
    let mut plaintext = vec![0u8; K];
    plaintext.extend_from_slice(payload);

    let mut block = plaintext.clone();
    cipher.encrypt_in_place(&mut block)?;

    // tamper with the ciphertext
    block[K + 5] ^= 0x01;

    cipher.decrypt_in_place(&mut block)?;

    if block[..K].iter().all(|&b| b != 0) {
        println!("tampering detected i.e. zero-prefix check failed");
    }

    Ok(())
}
