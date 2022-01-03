## Version: 0.1.29122021
- Added version
- privatekey_loop_h160_sse for using SSE advantage and privatekey_loop_h160 for old cpu
- pbkdf2_hmac_sha512_list for working on a list of mnemonics at once
- b58_encode and b58_decode added for base58 functions.
- address_to_h160 and bech32_address_decode for converting back from address to hash160
- Allowed return in bytes form of ETH functions. privatekey_to_ETH_address_bytes, privatekey_group_to_ETH_address_bytes, pubkey_to_ETH_address_bytes
- point_multiplication added __rmul__ accidental usage
- WIF format usage added. btc_wif_to_pvk_hex, btc_wif_to_pvk_int, btc_pvk_to_wif
- Pointer Memory leakage Fix of issue #8
- Fixed issue #5 of Zero Point Handling in different functions include vectors and sequentials
- Added bloom functions based on xxhash. bloom_check_add, bloom_batch_add, test_bit_set_bit
- Added sequential increment of NonG point using point_sequential_increment_P2 with initilization in init_P2_Group


## Version: ----
- Initial release of secp256k1 functions
- Python Library for Secp256k1 Bitcoin curve to do fast ECC calculation (3.49 Million/s per cpu)