# mruby-libsodium

mruby wrapper for https://github.com/jedisct1/libsodium

Breaking change in one of the latest commits: removed Sodium.memcmp, added Sodium::SecureBuffer#==
If you need a secure comparising function, take a look at https://github.com/Asmod4n/mruby-secure-compare

currently supported functions
```
sodium_bin2hex
sodium_hex2bin
```
```
randombytes_random
randombytes_uniform
randombytes_buf
```
```
crypto_secretbox
crypto_secretbox_open
```
```
crypto_auth
crypto_auth_verify
```
```
crypto_aead_chacha20poly1305_encrypt
crypto_aead_chacha20poly1305_decrypt
```
```
crypto_box_keypair
crypto_box_seed_keypair
crypto_box_easy
crypto_box_open_easy
```
```
crypto_sign_keypair
crypto_sign_seed_keypair
crypto_sign
crypto_sign_open
crypto_sign_detached
crypto_sign_verify_detached
```
```
crypto_generichash
crypto_generichash_init
crypto_generichash_update
crypto_generichash_final
```
```
crypto_pwhash
crypto_pwhash_str
crypto_pwhash_str_verify
crypto_pwhash_scryptsalsa208sha256
crypto_pwhash_scryptsalsa208sha256_str
crypto_pwhash_scryptsalsa208sha256_str_verify
```
Namespaces are taken from libsodium

Aka crypto_generichash gets ported as Crypto.generichash in Ruby and crypto_aead_chacha20poly1305_encrypt gets ported as Crypto::AEAD::Chacha20Poly1305.encrypt

There is no beautification done, all arguments must be passed like they are in C to keep a good performance.
The only addition done is length and return value checking.

The keypair functions return a hash with the following fields: :primitive, :public_key, :secret_key
There are helper functions go get keys and nonces for functions who need them.

sodium_malloc, sodium_free, sodium_mprotect_noaccess, sodium_mprotect_readonly, sodium_mprotect_readwrite are wrapped in a class: Sodium::SecureBuffer, which gets returned by the pwhash key generation functions.

Until everything is ported and documented, take a look at the excelent libsodium documentation https://download.libsodium.org/doc/
