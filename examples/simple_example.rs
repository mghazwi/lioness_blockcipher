use lioness_blockcipher::{Lioness, MasterKey};

fn main() -> anyhow::Result<()> {
    let key: MasterKey = [0x42; 32];

    let cipher = Lioness::new(&key);

    // Blocks must be at >32 bytes long
    let mut block = b"this is a long plaintext block and must stay a secret".to_vec();
    let original = block.clone();

    cipher.encrypt_in_place(&mut block)?;

    cipher.decrypt_in_place(&mut block)?;

    assert_eq!(block, original);
    println!("success!");

    Ok(())
}
