# secp256k1
Python Library for Secp256k1 Bitcoin curve to do fast ECC calculation (3.49 Million/s per cpu)

# Info
```
Some functions have been added for easier and quicker use in a script.
A Point is just a bytes form of correct length Full Pubkey. So 65 bytes exactly.

point_loop_addition is just like starting from a point P and incrementing +G continuously m times. So we get P+G, P+2G, P+3G...... All these are returned concatenated in 65bytes*m.
Same is the case with point_vector_addition but here two Point vectors are added together. Lets say 10points of 650bytes added with 10points of 650bytes to get added 650bytes.
point_sequential_increment is similar to loop_increment except some vector trick is used to make it faster.
Proper Zero Point handling added in functions.

Many Altcoin Address support has been added. Although not checked all of them. 
```

# Example Usage
```
import secp256k1 as ice
print('[C]',ice.privatekey_to_address(0, True, 42866423864328564389740932742094))
: [C] 1EAKqa4DbqnxJ9uLUFrXTMSPd2k3fHzWgr
print('[U]',ice.privatekey_to_address(0, False, 42866423864328564389740932742094))
: [U] 1SXCEWFyUp6q4x92iR6JANNDAu87MNmSz
print('[P2SH]',ice.privatekey_to_address(1, True, 42866423864328564389740932742094))
: [P2SH] 3BDxuSY3g7SM2Zg3k6pkYxCgvk2JbcCx3M
print('[Bech32]',ice.privatekey_to_address(2, True, 42866423864328564389740932742094))
: [Bech32] bc1qjpw34q9px0eaqmnut2vfxndkthlh5qs9gt969u


print(ice.scalar_multiplication(33604).hex())
: 0488de60bd8c187071fc486979f2c9696c3602c562fbba6922993ff665eae81b4f8adf94f4e2a50b05fe35aee42c146f6415e5cf524b6b1b5a8d17de8b741a5a21

P = ice.scalar_multiplication(33604)
P.hex()
: '0488de60bd8c187071fc486979f2c9696c3602c562fbba6922993ff665eae81b4f8adf94f4e2a50b05fe35aee42c146f6415e5cf524b6b1b5a8d17de8b741a5a21'

ice.point_negation(P).hex()
: '0488de60bd8c187071fc486979f2c9696c3602c562fbba6922993ff665eae81b4f75206b0b1d5af4fa01ca511bd3eb909bea1a30adb494e4a572e821738be5a20e'

ice.point_doubling(P).hex()
: '04484200af427941631f87f4ca153635156ceb0306e7033874e06a784088be5e3563868c14b34af7bc6206bcdbd63dee7a7825e595f8c45b07746e1b87da3091fc'

ice.point_multiplication(P, 7).hex()
: '048ea2016371a8e644f84252993527896b4c4d024a3e4e6c18246eb71b9c10363375be5a09dd9eaa819cdd50710309b5cc854aa910822be36cb28f88511132e4ce'

Pn = ice.scalar_multiplications([43242, 543053, 329074523, 321785444032743])
Pn[-65:].hex()
: '04fe34b4c918a738c61f8e1fa594c737f452eba2f6a84a2f7912c0c4dc91957e4b0ca6ba19ef14bfbf08c21f2f69a93067eb99d9d08d069ee556dbfe17abfa931a'

ice.pubkey_to_address(0, True, P)
: '17eCpwzTCEDAbws2ucoZEy1iEcg1WrLKDp'

ice.pubkey_to_address(0, False, P)
: '1Ew5GpHRfXskxurzUHyaf9WwV9NdxHWdch'

ice.pubkey_to_address(1, False, P)
: ' P2SH: Only compressed key '

ice.pubkey_to_address(1, True, P)
: '382NUCrzpd9WkpyRzEtusMM5e6v5tNCHQg'

ice.pubkey_to_address(2, True, P)
: 'bc1qfrdqfz89qxllsg3wrj46f9pegung0n8vj53fsk'

ice.privatekey_to_h160(1, True, 0x437af32d9e723fb9cd0).hex()
: '2ab7b63dd0de957b72df9eded24cd62e80d131f4'

ice.privatekey_to_h160(1, False, 0x437af32d9e723fb9cd0).hex()
: '3243394361fceaa57ae1a7ff32b48e30e8de3e5b'

ice.pbkdf2_hmac_sha512_dll('good push broken people salad bar mad squirrel joy dismiss merge jeans token wear boring manual doll near sniff turtle sunset lend invest foil').hex()
: '87aad6885223fa91dbca6f0a1f1816202832fd4264dc89365c745c0f1b0418d9065e33c2583cd8fb7f6f40c3dca65dec47dd7061105819833e630b6ebf085862'

P3 = ice.point_loop_addition(100000, P, P2)
P3[:65].hex()
: '044d7161f5d186b0f453887cd74a0f684534eb334da2b0ddcb9b9e9c6d3060d4ec1ae05b6da9d17c0aa6c2ffe6d5bd43a13cc52e0ec2463ca92d271b878b8ed464'

P3[-65:].hex()
: '047ae2dadd8871465f988a40e57d9ff7f37eb67f4d244df11b010995a92dcdebaa040d43b7895e538b3b83789e3ab98faf6b9b4201d5a2ed7d4b0f11b1d59b853d'

P4 = ice.point_sequential_increment(500000, P)
P4[:65].hex()
: '046ebfe8cd423c6c16fa29ce8aae12fa15b4ab78314773aa6453aa98b2bdcc10f66a43166c2f45267331dcf4a113aa584cd040fb0f8fe07326c28a8cb6b0f84149'

ice.btc_pvk_to_wif(0x4732861b1f)
: 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9R7rErzLE79yTdy'
ice.btc_pvk_to_wif(305790327583)
: 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9R7rErzLE79yTdy'
ice.btc_pvk_to_wif('4732861b1f')
: 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9R7rErzLE79yTdy'
ice.btc_pvk_to_wif(b'G2\x86\x1b\x1f')
: 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9R7rErzLE79yTdy'

ice.btc_pvk_to_wif(0x4732861b1f, False)
: '5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB4eoVyBj2oWsCR'

ice.btc_wif_to_pvk_hex('KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9R7rErzLE79yTdy')
: '0000000000000000000000000000000000000000000000000000004732861b1f'

ice.address_to_h160('151F838jqc92vshQNBXXf95hSW5hHbXHDq')
: '2bec4a80756fae715eec388727dacbca9ec34b54'

ice.bech32_address_decode('bc1q90ky4qr4d7h8zhhv8zrj0kkte20vxj65uft745')
: '2bec4a80756fae715eec388727dacbca9ec34b54'
ice.bech32_address_decode('ltc1q90ky4qr4d7h8zhhv8zrj0kkte20vxj65c436dy', ice.COIN_LTC)
: '2bec4a80756fae715eec388727dacbca9ec34b54'

ice.pubkey_to_ETH_address(P)
: '0xfa7e4d39a1fde2d03d01e298c31ee602bcdf4c85'

ice.privatekey_to_ETH_address(43789543)
: '0xf91262290187f5547839ae0c84b55892f39c5a9b'

ice.privatekey_to_ETH_address_bytes(43789543).hex()
: 'f91262290187f5547839ae0c84b55892f39c5a9b'

ice.privatekey_group_to_ETH_address(43232, 4)
: 'a760b12246759d603cca3686b95b1309772e9c30481fe3d921db92f0a0ad0012a852f0eaf05784feec0c24da5eeed9e7a6eb4477ee030289bf68311863b57e0e653620747c2339f48ba8cd60ea33ea88'

ice.pub_endo1(P).hex()
: '0441d68a94e621d33139103b6e4b9d8ac94103ba746952e4b322b7e7ba8c1d75d18adf94f4e2a50b05fe35aee42c146f6415e5cf524b6b1b5a8d17de8b741a5a21'

ice.pub_endo2(P).hex()
: '04354b14ad8dc5bc5ccaa75b17c1990bca88f980289af2b22a440821de88fa6b0f8adf94f4e2a50b05fe35aee42c146f6415e5cf524b6b1b5a8d17de8b741a5a21'

ice.get_sha256('S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy').hex()
: '4c7a9640c72dc2099f23715d0c8a0d8a35f8906e3cab61dd3f78b67bf887c9ab'

ice.get_sha256(P).hex()
: '739c4ba018e1877d5c82fa60b7e2304776e7bf39af5dc9b4c05152ea78b822f9'

ice.privatekey_to_coinaddress(ice.COIN_LTC, 0, True, 0x1b1f)
: 'LPb9na7qWdM7iHwKiiQmkQrhBtr11n8ywb'

ice.privatekey_to_coinaddress(ice.COIN_DOGE, 0, True, 0x1b1f)
: 'D9WJ4ckejP1LzVRmHAR329xXrpD2HhkX4Q'

ice.privatekey_to_coinaddress(ice.COIN_DOGE, 0, False, 0x1b1f)
: 'D7Q1YeimeNmgmn4HnRGJnFrpMkQWJK3bHn'

ice.privatekey_to_coinaddress(ice.COIN_DASH, 0, True, 0x1b1f)
: 'Xf43McTuPgKecRqkQTjhKvUip24Qza1qRF'

ice.privatekey_to_coinaddress(ice.COIN_RVN, 0, True, 0x1b1f)
: 'RDePbshJ2nudXVcN1kQbZv88jwwKWs42X6'

ice.checksum('What is the use of it?').hex()
: '6bbe6051'

xx = ['43253', 'hfoiefcope', 'cvt9', '4329r32hf39', '4e329jf4iehgf43']
_bits, _hashes, _bf, _fp, _elem = ice.Fill_in_bloom(xx, 0.000001)
print(ice.check_in_bloom('cvt9', _bits, _hashes, _bf))
: True

ice.dump_bloom_file("my_bloom_file.bin", _bits, _hashes, _bf, _fp, _elem)
_bits, _hashes, _bf, _fp, _elem = ice.read_bloom_file("my_bloom_file.bin")
print(ice.check_in_bloom('cvt9', _bits, _hashes, _bf))
: True

ice.bsgs_2nd_check_prepare(100000000)
Q = ice.scalar_multiplication(0x10000000000000000000000005820545)
found, pvk = ice.bsgs_2nd_check(Q, 0x10000000000000000000000000000000, 100000000)
print(found, pvk.hex())
:  True 0000000000000000000000000000000010000000000000000000000005820545

P = ice.pub2upub('02CEB6CBBCDBDF5EF7150682150F4CE2C6F4807B349827DCDBDD1F2EFA885A2630')
print(P.hex())
: '04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac'

ice.point_to_cpub(P)
: '02ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a2630'

ice.to_cpub('04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac')
: '02ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a2630'

ice.prepare_bin_file("eth_addr_file.txt", "eth_sorted.bin", True, True)
ice.Load_data_to_memory("eth_sorted.bin", False)
ice.check_collision(this_key_eth_bytes)
: True

```
# Speed
On my old Laptop with i7 4810 MQ CPU
```
timeit ice.privatekey_to_address(0, True, 67)
6.35 µs ± 41.4 ns per loop (mean ± std. dev. of 7 runs, 100000 loops each)

timeit ice.scalar_multiplication(3240945)
3.1 µs ± 38.7 ns per loop (mean ± std. dev. of 7 runs, 100000 loops each)

timeit ice.point_multiplication(P, 25465786)
13 µs ± 98.4 ns per loop (mean ± std. dev. of 7 runs, 100000 loops each)

timeit ice.point_increment(P)
2.32 µs ± 20.6 ns per loop (mean ± std. dev. of 7 runs, 100000 loops each)

timeit ice.point_addition(P,P2)
2.66 µs ± 17.6 ns per loop (mean ± std. dev. of 7 runs, 100000 loops each)
```
With 3500000 continuous keys in 1 group call, we get 3.5 Miilion Key/s Speed with 1 cpu:
```
timeit ice.point_sequential_increment(3500000, P)
817 ms ± 15.3 ms per loop (mean ± std. dev. of 7 runs, 1 loop each)
```
