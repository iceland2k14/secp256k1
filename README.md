# secp256k1
Python Library for Secp256k1 Bitcoin curve to do fast ECC calculation (3.49 Million/s per cpu)

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

ice.pubkey_to_ETH_address(P)
: '0xfa7e4d39a1fde2d03d01e298c31ee602bcdf4c85'

ice.privatekey_to_ETH_address(43789543)
: '0xf91262290187f5547839ae0c84b55892f39c5a9b'

ice.privatekey_group_to_ETH_address(43232, 4)
: 'a760b12246759d603cca3686b95b1309772e9c30481fe3d921db92f0a0ad0012a852f0eaf05784feec0c24da5eeed9e7a6eb4477ee030289bf68311863b57e0e653620747c2339f48ba8cd60ea33ea88'
```
# Speed
On my old Laptop with i7 4810 MQ CPU
```
timeit ice.privatekey_to_address(0, True, 67)
6.35 µs ± 41.4 ns per loop (mean ± std. dev. of 7 runs, 100000 loops each)

timeit ice.scalar_multiplication(3240945)
3.1 µs ± 38.7 ns per loop (mean ± std. dev. of 7 runs, 100000 loops each)

timeit ice.point_increment(P)
2.32 µs ± 20.6 ns per loop (mean ± std. dev. of 7 runs, 100000 loops each)

timeit ice.point_addition(P,P2)
2.66 µs ± 17.6 ns per loop (mean ± std. dev. of 7 runs, 100000 loops each)
```
With 3500000 continuous keys in 1 group call, we get 3.5 Miilion Key/s Speed with 1 cpu:
```
timeit ice.point_sequential_increment(3500000, P)
1.01 s ± 5.37 ms per loop (mean ± std. dev. of 7 runs, 1 loop each)
```
