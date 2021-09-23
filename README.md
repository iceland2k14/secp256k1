# secp256k1
Python Library for Secp256k1 Bitcoin curve to do fast ECC calculation

# Example Usage
```
import secp256k1 as ice
print('[C]',privatekey_to_address(0, True, 42866423864328564389740932742094))
```
# Speed
On my old Laptop with i7 4810 MQ CPU
```
timeit ice.privatekey_to_address(0, True, 67)
7.13 µs ± 359 ns per loop (mean ± std. dev. of 7 runs, 100000 loops each)

timeit ice.scalar_multiplication(3240945)
3.1 µs ± 38.7 ns per loop (mean ± std. dev. of 7 runs, 100000 loops each)

timeit ice.point_increment(P)
2.76 µs ± 267 ns per loop (mean ± std. dev. of 7 runs, 100000 loops each)

timeit ice.point_addition(P,G)
2.91 µs ± 35.4 ns per loop (mean ± std. dev. of 7 runs, 100000 loops each)

With 500000 continuous keys in 1 group call, we get :
timeit ice.privatekey_group_to_ETH_address(256, 500000)
1.55 s ± 2.53 ms per loop (mean ± std. dev. of 7 runs, 1 loop each)
```
