
### Lioness wide-block cipher.

### Warning

This code has not been formally audited, Use at your own risk or ask a cryptographers before use.

### Overview

[Lioness](https://www.cl.cam.ac.uk/~rja14/Papers/bear-lion.pdf) is a wide block cipher built from 
- `S`: Stream cipher, 
- `H`: Keyed-Hash function,
- `K`: Key derivation function (KDF) to derive the 4 internal round keys

Any secure compatible options and their combinations can work, in this crate we have the following options:
- `S`: AES-CTR-128, Chacha20
- `H`: keyed-Blake2b, HMAC-SHA-256, SHA-256 (with key prepend) 
- `K`: TURBOSHAKE-128, SHAKE-128, HKDF-SHA-256, domain-seperated SHA-256

These primitives are imported from: 
- [rustcrypto streamciphers](https://github.com/RustCrypto/stream-ciphers)
- [rustcrypto hashes](https://github.com/RustCrypto/hashes/tree/master)

The security of lioness reduce to the security of the underlying stream cipher or
the hash function.  
See the [paper](https://www.cl.cam.ac.uk/~rja14/Papers/bear-lion.pdf) for more information. 

### How to use

Here is an example of how to use the `Lioness_blockcipher` create. 
Use a 32-byte master key and encrypt or decrypt a block in place:

```rust
use rand_core::{OsRng, RngCore};
use lioness_blockcipher::prelude::*;
type TestLioness = Lioness::<
    ChaCha20StreamCipher,
    KeyedBlake2b,
    TurboShake128Kdf
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
```

Some notes:

- Encryption and decryption are both in-place for now.
- The block length need to be bigger than `64` bytes because Lioness splits the block into two where the left part is 32-byte, and the right part needs at least 16 bytes. might support small blocks in the future, but for Sphinx use-case, this should work.
- If you need authenticity, make sure to use `encrypt_in_place_auth` which prepends the plaintext with 128-bits zeros. Also use `decrypt_in_place_auth` to check the zeros after decryption. see [authentication example](./examples/auth)

### TODO
- [x] Add more tests, examples, and benchmarks ...
- [x] Make it generic for any compatible cipher, keyed_hash, and KDF. 
- [ ] Compare with existing implementation + maybe with Haskel when available.
- [x] Add function which prepend the plaintext with k-zeros and checks authenticity after decryption.
- [ ] impl enc and dec to the API to work beside encrypt_in_place and decrypt_in_place.
- ...
