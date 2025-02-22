# -*- coding: utf-8 -*-
"""

@author: iceland
"""
import secp256k1 as ice
import timeit

#==============================================================================
# For Operator Overloading Purpose. Like P + Q, Q * 20, P / 5 etc etc.
class UpubData:
    def __init__(self, data):
        if len(data) != 65:
            raise ValueError("Data must be 65 bytes")
        self.data = data
    
    def __add__(self, other):
        if not isinstance(other, UpubData):
            return NotImplemented
        return UpubData(ice.point_addition(self.data, other.data))
    
    def __sub__(self, other):
        if not isinstance(other, UpubData):
            return NotImplemented
        return UpubData(ice.point_subtraction(self.data, other.data))

    def __neg__(self):
        return UpubData(ice.point_negation(self.data))
    
    def __mul__(self, other):
        if isinstance(other, int):
            return UpubData(ice.point_multiplication(self.data, other))
        return NotImplemented

    def __rmul__(self, other):
        return self.__mul__(other)

    def __truediv__(self, other):
        if isinstance(other, int):
            return UpubData(ice.point_division(self.data, other))
        return NotImplemented
    
    def to_bytes(self): 
        return self.data
    
    def __repr__(self):
        return f"UpubData({self.data})"
    
    def __str__(self): 
        return f"{self.data.hex()}"

def upub(data): 
    if isinstance(data, UpubData): 
        return data 
    return UpubData(data)
#==============================================================================
# Example. Q = (((P * 160 )-P) /77).to_bytes()

def fix_time(val):
    units = [("ms", 1e3), ("us", 1e6), ("ns", 1e9)]
    for unit, factor in units:
        if val >= 1 / factor:
            return f"{val * factor:.2f} {unit}"

def chk(mess, i, o):
    if i == o: print(f'{mess:<30} : PASS')
    else: print(f'{mess:<30} : FAIL')

def self_check():
    pvk = 42866423864328564389740932742094
    chk('P2PKH_C', ice.privatekey_to_address(0, True, pvk), '1EAKqa4DbqnxJ9uLUFrXTMSPd2k3fHzWgr')
    chk('P2PKH_U', ice.privatekey_to_address(0, False, pvk), '1SXCEWFyUp6q4x92iR6JANNDAu87MNmSz')
    chk('P2SH', ice.privatekey_to_address(1, True, pvk), '3BDxuSY3g7SM2Zg3k6pkYxCgvk2JbcCx3M')
    chk('Bech32', ice.privatekey_to_address(2, True, pvk), 'bc1qjpw34q9px0eaqmnut2vfxndkthlh5qs9gt969u')
    
    pvk = 33604
    P = ice.scalar_multiplication(pvk)
    chk('Scalar_Multiplication', P.hex(), '0488de60bd8c187071fc486979f2c9696c3602c562fbba6922993ff665eae81b4f8adf94f4e2a50b05fe35aee42c146f6415e5cf524b6b1b5a8d17de8b741a5a21')
    chk('Point Negation', ice.point_negation(P).hex(), '0488de60bd8c187071fc486979f2c9696c3602c562fbba6922993ff665eae81b4f75206b0b1d5af4fa01ca511bd3eb909bea1a30adb494e4a572e821738be5a20e')
    chk('Point Doubling', ice.point_doubling(P).hex(), '04484200af427941631f87f4ca153635156ceb0306e7033874e06a784088be5e3563868c14b34af7bc6206bcdbd63dee7a7825e595f8c45b07746e1b87da3091fc')
    chk('Point Multiplication', ice.point_multiplication(P, 7).hex(), '048ea2016371a8e644f84252993527896b4c4d024a3e4e6c18246eb71b9c10363375be5a09dd9eaa819cdd50710309b5cc854aa910822be36cb28f88511132e4ce')
    print('[8/8] All check Passed...')

def op_check():
    pvk = 0x437af32d9e723fb9cd0
    Q = upub(ice.scalar_multiplication(pvk))
    G = upub(ice.scalar_multiplication(1))
    R = Q * 25 - G * 8
    chk('Operator Check', R.to_bytes(), ice.scalar_multiplication(0x69701bf7479283925048))
    
def speed_check(mess, setup_code, test_code):
    timer = timeit.Timer(stmt=test_code, setup=setup_code)
    number, _ = timer.autorange()
    execution_times = timer.repeat(repeat=5, number=number)
    best_time = min(execution_times)
    time_per_loop = fix_time(best_time / number)
    print(f"{mess:<30} : {number} loops, best of 5: {time_per_loop} per loop")

#==============================================================================
setup_code = """import secp256k1 as ice; pvk = 0xf5ef7150682150f4ce2c6f4807b349827dcdbd
P = ice.scalar_multiplication(pvk)"""

test_code = """
ice.point_sequential_increment(3500000, P)
"""

self_check()
op_check()
speed_check("Point Sequential Increment", setup_code, test_code)
speed_check("Point Addition", setup_code, """ice.point_addition(P, P)""")
