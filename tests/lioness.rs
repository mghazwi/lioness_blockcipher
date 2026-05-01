#[cfg(test)]
mod tests {
    use rand_core::{OsRng, RngCore};
    use lioness_blockcipher::cipher::Aes128CtrStreamCipher;
    use lioness_blockcipher::kdf::DomSepSha256Kdf;
    use lioness_blockcipher::keyed_hash::HmacSha256KeyedHash;
    use lioness_blockcipher::prelude::*;
    type TestLioness = Lioness::<
        Aes128CtrStreamCipher,
        HmacSha256KeyedHash,
        DomSepSha256Kdf
        >;
    fn get_test_key() -> Key256 {
        let mut key: Key256 = Default::default();
        OsRng.fill_bytes(&mut key);
        key
    }

    #[test]
    fn rejects_short_blocks() {
        let cipher: TestLioness = Lioness::new(&get_test_key()).expect("invalid master key");
        let mut block = [0u8; K_256];

        assert!(cipher.encrypt_in_place(&mut block).is_err());
    }

    #[test]
    fn enc_dec_round_trip() {
        let cipher: TestLioness = Lioness::new(&get_test_key()).expect("invalid master key");
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
        let cipher_a: TestLioness = Lioness::new(&key).expect("invalid master key");
        let cipher_b: TestLioness = Lioness::new(&key).expect("invalid master key");
        let mut outa = vec![0x42u8; 512];
        let mut outb = outa.clone();

        cipher_a.encrypt_in_place(&mut outa).unwrap();
        cipher_b.encrypt_in_place(&mut outb).unwrap();
        assert_eq!(outa, outb);
    }
}