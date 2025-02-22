## Version: 0.1.16022025
- Bugfix in load_bsgs_2nd. Reduced the overall size requirement of bsgs_2nd
- Added bsgs_2nd_check_mcpu for checking all pubkeys together using multicpu
- Generalized verify_message for other r/-r, s/-s cases
- Shifted UpubData class to benchmark script


## Version: 0.1.29012025
- Changed hash function inside XOR Filter to xxhash
- Revert back to -O2 compilation flag for varsatile usability .Fixed #63
- Bugfix in bsgs_xor_create_mcpu for Element G
- Minor speedup in create_valid_mnemonics


## Version: 0.1.12012025
- Integer with >N is handled in fl as Mod_N
- Fixed #61
- Added dump_bsgs_2nd / load_bsgs_2nd to dump / load the bsgs_2nd_check_prepare data to binary file.
- In bsgs_2nd_check removed extra argument bP_elem
- Added check_collision_mcpu as an extension of check_collision to use mcpu
- Added rmd160 for RIPEmd160 and hash160 as RIPEmd160(SHA256)
- Added create_burn_address for p2pkh compressed btc address to have some fun
- Added point_division as a wrapper of inverse using point_multiplication
- Added Operator Overloading class UpubData for (+/-*) simplification. Beware of runtime overhead
- Added XOR Filter functions xor_para, fill_in_xor, dump_xor_file, read_xor_file, check_in_xor
- Added bsgs_xor_create_mcpu for creating XOR filters using bsgs algo with multi cpu
- Added check_in_xor_mcpu for multicpu search


## Version: 0.1.27032024
- Bugfix bloom_check_add_mcpu
- Added one_to_6pubkey and one_to_6privatekey using symmetry and endomorphism property
- Check if the Pubkey is on the curve using pubkey_isvalid
- Added chunks for easy slicing of returned pubkey bytes
- Added verify_message for bitcoin signature verification and rsz, pubkey extraction
- Added sha512, hmac_sha512, bip39seed_to_bip32masternode and mnemonics_to_bip32masternode
- Added parse_derivation_path for single and range of childkeys using (0-5)
- Mnemonics generation with create_valid_mnemonics for English
- mnem_to_privatekey, mnem_to_address wrapper for simplication of intermediate steps (single or range)
- Privatekey for any derivation BIP44,49,84 BTC and maybe altcoin by specifying SLIP0044
- root_key and fingerprint added. Not updated till xprv, xpub of Extended pvk,pub
- pubkey_to_coinaddress added for #41 issue
- bech32_address_decode modified for p2wsh. pubkey_to_p2wsh_address added.


## Version: 0.1.18062023
- Bugfix bloom_check_add_mcpu
- Shifted functionalities from BSGS.dll to this library using create_bsgs_bloom_mcpu
- Added addional check functions bsgs_2nd_check_prepare and bsgs_2nd_check to use in bsgs algo
- Fill_in_bloom now also return the false probability and number of elements
- dump_bloom_file and read_bloom_file takes also these 2 extra arguments _fp and _elem
- Added function scalar_multiplications for multiple privatekey to Pubkey together from list of keys
- transfer function point_multiplication to c++ for faster calculation
- Incorporated PR39


## Version: 0.1.18052022
- Added checksum for sha256
- Unsupported type ERROR in fl now print detected Type
- Pubkey conversion functions added pub2upub, to_cpub, point_to_cpub
- function bloom_check_add_mcpu added for later use
- bloom_para, Fill_in_bloom, check_in_bloom helpful wrappers for bloom creation and test
- prepare_bin_file, prepare_bin_file_work ideally to be used with rmd or eth to create .bin file
- Once created the bloom can be saved and reloaded by dump_bloom_file, read_bloom_file
- Option from .bin sorted file __20 byte each item__ to directly load into RAM using Load_data_to_memory
- check for existence using check_collision function alongside Load_data_to_memory


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