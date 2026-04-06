
### Lioness large-block cipher with ChaCha20, Blake2b, and Turboshake.

### Warning

This code has not been formally audited, Use at your own risk or ask a cryptographers before use.

### Overview

[Lioness](https://www.cl.cam.ac.uk/~rja14/Papers/bear-lion.pdf) is a large block cipher built from 
- Stream cipher, 
- Hash function,
- Key derivation function (KDF), although this can be remove if the input key is large enough to cover the four sub-keys used.

In here we use:
- Chacha20 from [rustcrypto streamciphers](https://github.com/RustCrypto/stream-ciphers)
- Blake2b from [rustcrypto hashes](https://github.com/RustCrypto/hashes/tree/master)
- turboshake KDF from [rustcrypto SHA3](https://github.com/RustCrypto/hashes/tree/master/sha3)

The security of lioness reduce to the security of the underlying stream cipher or
the hash function.  
See the [paper](https://www.cl.cam.ac.uk/~rja14/Papers/bear-lion.pdf) for more information. 

### How to use

Here is an example of how to use the `Lioness_blockcipher` create. 
Use a 32-byte master key and encrypt or decrypt a block in place:

```rust
use lioness_blockcipher::{Lioness, MasterKey};

fn main() -> anyhow::Result<()> {
    let mut key: MasterKey = [0x42; 32];

    let cipher = Lioness::new(&key);

    // Blocks must be at >32 bytes long
    let mut block = b"this is a long plaintext block and must stay a secret".to_vec();
    let original = block.clone();

    cipher.encrypt_in_place(&mut block)?;

    cipher.decrypt_in_place(&mut block)?;
    
    assert_eq!(block, original);

    Ok(())
}
```

Some notes:

- Encryption and decryption are both in-place for now.
- The block length need to be bigger than `32` bytes because Lioness splits the block into two where the left part is 32-byte, and the right part can't be empty. might support small blocks in the future, but for Sphinx use-case, this should work.
- If you need authenticity, make sure to prepend the plaintext with `k` zeros and check the zeros after decryption. This will be supported in the future... see [integrity example](./examples/integrity.rs)

### TODO
- [ ] Add more tests, examples, and benchmarks ...
- [ ] Make it generic for any compatible cipher, keyed_hash, and KDF. 
- [ ] Compare with another implementation ... maybe with Haskel when available.
- [ ] Add a version with API which prepend the plaintext with k-zeros and checks authenticity after decryption.
- [ ] impl enc and dec to the API to work beside encrypt_in_place and decrypt_in_place.
- ...
