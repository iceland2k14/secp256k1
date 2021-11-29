# -*- coding: utf-8 -*-
"""

@author: iceland
"""

import platform
import os
import sys
import ctypes


###############################################################################
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
Zero=b'\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
#==============================================================================
if platform.system().lower().startswith('win'):
    dllfile = 'ice_secp256k1.dll'
    if os.path.isfile(dllfile) == True:
        pathdll = os.path.realpath(dllfile)
        ice = ctypes.CDLL(pathdll)
    else:
        print('File {} not found'.format(dllfile))
    
elif platform.system().lower().startswith('lin'):
    dllfile = 'ice_secp256k1.so'
    if os.path.isfile(dllfile) == True:
        pathdll = os.path.realpath(dllfile)
        ice = ctypes.CDLL(pathdll)
    else:
        print('File {} not found'.format(dllfile))
    
else:
    print('[-] Unsupported Platform currently for ctypes dll method. Only [Windows and Linux] is working')
    sys.exit()
###############################################################################
#==============================================================================
# Coin type
COIN_BTC  = 0
COIN_BSV  = 1
COIN_BTCD = 2
COIN_ARG  = 3
COIN_AXE  =	4
COIN_BC   = 5
COIN_BCH  = 6
COIN_BSD  =	7
COIN_BTDX = 8 
COIN_BTG  =	9
COIN_BTX  =	10
COIN_CHA  =	11
COIN_DASH = 12
COIN_DCR  =	13
COIN_DFC  =	14
COIN_DGB  =	15
COIN_DOGE = 16
COIN_FAI  =	17
COIN_FTC  =	18
COIN_GRS  =	19
COIN_JBS  =	20
COIN_LTC  =	21
COIN_MEC  =	22
COIN_MONA = 23
COIN_MZC  =	24
COIN_PIVX = 25
COIN_POLIS= 26
COIN_RIC  = 27
COIN_STRAT= 28
COIN_SMART= 29
COIN_VIA  = 30
COIN_XMY  =	31
COIN_ZEC  =	32
COIN_ZCL  =	33
COIN_ZERO = 34
COIN_ZEN  =	35
COIN_TENT = 36
COIN_ZEIT = 37
COIN_VTC  =	38
COIN_UNO  =	39
COIN_SKC  =	40
COIN_RVN  =	41
COIN_PPC  =	42
COIN_OMC  =	43
COIN_OK   =	44
COIN_NMC  =	45
COIN_NLG  =	46
COIN_LBRY =	47
COIN_DNR  =	48
COIN_BWK  =	49
#==============================================================================

ice.scalar_multiplication.argtypes = [ctypes.c_char_p, ctypes.c_char_p]            # pvk,ret
#==============================================================================
# ice.point_multiplication.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]   # upub,scalar,ret
#==============================================================================
ice.get_x_to_y.argtypes = [ctypes.c_char_p, ctypes.c_bool, ctypes.c_char_p]   # x,even,ret
#==============================================================================
ice.point_increment.argtypes = [ctypes.c_char_p, ctypes.c_char_p] # upub,ret
#==============================================================================
ice.point_negation.argtypes = [ctypes.c_char_p, ctypes.c_char_p]  # upub,ret
#==============================================================================
ice.point_doubling.argtypes = [ctypes.c_char_p, ctypes.c_char_p]  # upub,ret
#==============================================================================
ice.privatekey_to_coinaddress.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_bool, ctypes.c_char_p]  # intcoin,012,comp,pvk
ice.privatekey_to_coinaddress.restype = ctypes.c_void_p
#==============================================================================
ice.privatekey_to_address.argtypes = [ctypes.c_int, ctypes.c_bool, ctypes.c_char_p]  # 012,comp,pvk
ice.privatekey_to_address.restype = ctypes.c_void_p
#==============================================================================
ice.hash_to_address.argtypes = [ctypes.c_int, ctypes.c_bool, ctypes.c_char_p]  # 012,comp,hash
ice.hash_to_address.restype = ctypes.c_void_p
#==============================================================================
ice.pubkey_to_address.argtypes = [ctypes.c_int, ctypes.c_bool, ctypes.c_char_p]  # 012,comp,upub
ice.pubkey_to_address.restype = ctypes.c_void_p
#==============================================================================
ice.privatekey_to_h160.argtypes = [ctypes.c_int, ctypes.c_bool, ctypes.c_char_p, ctypes.c_char_p]  # 012,comp,pvk,ret
#==============================================================================
ice.privatekey_loop_h160.argtypes = [ctypes.c_ulonglong, ctypes.c_int, ctypes.c_bool, ctypes.c_char_p, ctypes.c_char_p]  # num,012,comp,pvk,ret
#==============================================================================
ice.pubkey_to_h160.argtypes = [ctypes.c_int, ctypes.c_bool, ctypes.c_char_p, ctypes.c_char_p]  # 012,comp,upub,ret
#==============================================================================
ice.pbkdf2_hmac_sha512_dll.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int] # ret, words, len
#==============================================================================
ice.pub_endo1.argtypes = [ctypes.c_char_p, ctypes.c_char_p]  # upub,ret
#==============================================================================
ice.pub_endo2.argtypes = [ctypes.c_char_p, ctypes.c_char_p]  # upub,ret
#==============================================================================
# ice.b58_enc.argtypes = [ctypes.c_char_p]  # addr
# ice.b58_enc.restype = ctypes.c_void_p
#==============================================================================
ice.get_sha256.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p] # input, len, ret
#==============================================================================
ice.create_baby_table.argtypes = [ctypes.c_ulonglong, ctypes.c_ulonglong, ctypes.c_char_p] # start,end,ret
#==============================================================================
ice.point_addition.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p] # upub1,upub2,ret
#==============================================================================
ice.point_subtraction.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p] # upub1,upub2,ret
#==============================================================================
ice.point_loop_subtraction.argtypes = [ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p] # k,upub1,upub2,ret
#==============================================================================
ice.point_loop_addition.argtypes = [ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p] # k,upub1,upub2,ret
#==============================================================================
ice.point_vector_addition.argtypes = [ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p] # num,upubs1,upubs2,ret
#==============================================================================
ice.point_sequential_increment.argtypes = [ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p] # num,upub1,ret
#==============================================================================
ice.pubkeyxy_to_ETH_address.argtypes = [ctypes.c_char_p] # upub_xy
ice.pubkeyxy_to_ETH_address.restype = ctypes.c_void_p
#==============================================================================
ice.privatekey_to_ETH_address.argtypes = [ctypes.c_char_p] # pvk
ice.privatekey_to_ETH_address.restype = ctypes.c_void_p
#==============================================================================
ice.privatekey_group_to_ETH_address.argtypes = [ctypes.c_char_p, ctypes.c_int] # pvk, m
ice.privatekey_group_to_ETH_address.restype = ctypes.c_void_p
#==============================================================================
ice.free_memory.argtypes = [ctypes.c_void_p] # pointer
#==============================================================================

ice.init_secp256_lib()
#==============================================================================
###############################################################################


def _scalar_multiplication(pvk_int):
    ''' Integer value passed to function. 65 bytes uncompressed pubkey output '''
    res = (b'\x00') * 65
    pass_int_value = hex(pvk_int)[2:].encode('utf8')
    ice.scalar_multiplication(pass_int_value, res)
    return res
def scalar_multiplication(pvk_int):
    if pvk_int < 0: pvk_int = N+pvk_int
    res = _scalar_multiplication(pvk_int)
    return bytes(bytearray(res))
#==============================================================================
def point_multiplication(k, P):
    def bits(k):
        while k:
            yield k & 1
            k >>= 1
    result = Zero
    addend = P
    for bit in bits(k):
        if bit == 1: result=point_addition(result,addend)
        addend=point_doubling(addend)
    return result
# =============================================================================
# def _point_multiplication(pubkey_bytes, kk):
#     ''' Input Point and Integer value passed to function. 65 bytes uncompressed pubkey output '''
#     res = (b'\x00') * 65
#     bytes_value = bytes.fromhex(hex(kk)[2:].zfill(64))  # strict 32 bytes scalar
#     ice.point_multiplication(pubkey_bytes, bytes_value, res)
#     return res
# def point_multiplication(pubkey_bytes, kk):
#     res = _point_multiplication(pubkey_bytes, kk)
#     return bytes(bytearray(res))
# =============================================================================
#==============================================================================
def _get_x_to_y(x_hex, is_even):
    ''' Input x_hex encoded as bytes and bool is_even. 32 bytes y of point output '''
    res = (b'\x00') * 32
    ice.get_x_to_y(x_hex.encode('utf8'), is_even, res)
    return res
def get_x_to_y(x_hex, is_even):
    res = _get_x_to_y(x_hex, is_even)
    return bytes(bytearray(res))
#==============================================================================
def _point_increment(pubkey_bytes):
    res = (b'\x00') * 65
    ice.point_increment(pubkey_bytes, res)
    return res
def point_increment(pubkey_bytes):
    res = _point_increment(pubkey_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _point_negation(pubkey_bytes):
    res = (b'\x00') * 65
    ice.point_negation(pubkey_bytes, res)
    return res
def point_negation(pubkey_bytes):
    res = _point_negation(pubkey_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _point_doubling(pubkey_bytes):
    res = (b'\x00') * 65
    ice.point_doubling(pubkey_bytes, res)
    return res
def point_doubling(pubkey_bytes):
    res = _point_doubling(pubkey_bytes)
    return bytes(bytearray(res))
#==============================================================================
def privatekey_to_coinaddress(coin_type, addr_type, iscompressed, pvk_int):
    # type = 0 [p2pkh],  1 [p2sh],  2 [bech32]
    if pvk_int < 0: pvk_int = N+pvk_int
    pass_int_value = hex(pvk_int)[2:].encode('utf8')
    res = ice.privatekey_to_coinaddress(coin_type, addr_type, iscompressed, pass_int_value)
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addr
#==============================================================================
def privatekey_to_address(addr_type, iscompressed, pvk_int):
    # type = 0 [p2pkh],  1 [p2sh],  2 [bech32]
    if pvk_int < 0: pvk_int = N+pvk_int
    pass_int_value = hex(pvk_int)[2:].encode('utf8')
    res = ice.privatekey_to_address(addr_type, iscompressed, pass_int_value)
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addr
#==============================================================================
def hash_to_address(addr_type, iscompressed, hash160_bytes):
    # type = 0 [p2pkh],  1 [p2sh],  2 [bech32]
    res = ice.hash_to_address(addr_type, iscompressed, hash160_bytes)
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addr
#==============================================================================
def pubkey_to_address(addr_type, iscompressed, pubkey_bytes):
    # type = 0 [p2pkh],  1 [p2sh],  2 [bech32]
    res = ice.pubkey_to_address(addr_type, iscompressed, pubkey_bytes)
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addr
#==============================================================================
def _privatekey_to_h160(addr_type, iscompressed, pvk_int):
    # type = 0 [p2pkh],  1 [p2sh],  2 [bech32]
    if pvk_int < 0: pvk_int = N+pvk_int
    pass_int_value = hex(pvk_int)[2:].encode('utf8')
    res = (b'\x00') * 20
    ice.privatekey_to_h160(addr_type, iscompressed, pass_int_value, res)
    return res
def privatekey_to_h160(addr_type, iscompressed, pvk_int):
    res = _privatekey_to_h160(addr_type, iscompressed, pvk_int)
    return bytes(bytearray(res))
#==============================================================================
def _privatekey_loop_h160(num, addr_type, iscompressed, pvk_int):
    # type = 0 [p2pkh],  1 [p2sh],  2 [bech32]
    if pvk_int < 0: pvk_int = N+pvk_int
    pass_int_value = hex(pvk_int)[2:].encode('utf8')
    res = (b'\x00') * (20 * num)
    ice.privatekey_loop_h160(num, addr_type, iscompressed, pass_int_value, res)
    return res
def privatekey_loop_h160(num, addr_type, iscompressed, pvk_int):
    if num <= 0: num = 1
    res = _privatekey_loop_h160(num, addr_type, iscompressed, pvk_int)
    return bytes(bytearray(res))
#==============================================================================
def _pubkey_to_h160(addr_type, iscompressed, pubkey_bytes):
    # type = 0 [p2pkh],  1 [p2sh],  2 [bech32]
    res = (b'\x00') * 20
    ice.pubkey_to_h160(addr_type, iscompressed, pubkey_bytes, res)
    return res
def pubkey_to_h160(addr_type, iscompressed, pubkey_bytes):
    res = _pubkey_to_h160(addr_type, iscompressed, pubkey_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _pub_endo1(pubkey_bytes):
    res = (b'\x00') * 65
    ice.pub_endo1(pubkey_bytes, res)
    return res
def pub_endo1(pubkey_bytes):
    res = _pub_endo1(pubkey_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _pub_endo2(pubkey_bytes):
    res = (b'\x00') * 65
    ice.pub_endo2(pubkey_bytes, res)
    return res
def pub_endo2(pubkey_bytes):
    res = _pub_endo2(pubkey_bytes)
    return bytes(bytearray(res))
#==============================================================================
# =============================================================================
# def b58_enc(inp):
#     res = ice.b58_enc(inp)
#     addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
#     ice.free_memory(res)
#     return addr
# =============================================================================
#==============================================================================
def pbkdf2_hmac_sha512_dll(words):
    seed_bytes = (b'\x00') * 64
#    words = 'good push broken people salad bar mad squirrel joy dismiss merge jeans token wear boring manual doll near sniff turtle sunset lend invest foil'
    ice.pbkdf2_hmac_sha512_dll(seed_bytes, words.encode("utf-8"), len(words))
    return seed_bytes
#==============================================================================
def get_sha256(input_bytes):
    digest_bytes = (b'\x00') * 32
    if type(input_bytes) == str: input_bytes = input_bytes.encode("utf-8")
#    MiniKey example
    ice.get_sha256(input_bytes, len(input_bytes), digest_bytes)
    return digest_bytes
#==============================================================================
def create_baby_table(start_value, end_value):
    res = (b'\x00') * ((1+end_value-start_value) * 32)
    ice.create_baby_table(start_value, end_value, res)
    return bytes(bytearray(res))
#==============================================================================
def _point_addition(pubkey1_bytes, pubkey2_bytes):
    res = (b'\x00') * 65
    ice.point_addition(pubkey1_bytes, pubkey2_bytes, res)
    return res
def point_addition(pubkey1_bytes, pubkey2_bytes):
    res = _point_addition(pubkey1_bytes, pubkey2_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _point_subtraction(pubkey1_bytes, pubkey2_bytes):
    res = (b'\x00') * 65
    ice.point_subtraction(pubkey1_bytes, pubkey2_bytes, res)
    return res
def point_subtraction(pubkey1_bytes, pubkey2_bytes):
    res = _point_subtraction(pubkey1_bytes, pubkey2_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _point_loop_subtraction(num, pubkey1_bytes, pubkey2_bytes):
    res = (b'\x00') * (65 * num)
    ice.point_loop_subtraction(num, pubkey1_bytes, pubkey2_bytes, res)
    return res
def point_loop_subtraction(num, pubkey1_bytes, pubkey2_bytes):
    if num <= 0: num = 1
    res = _point_loop_subtraction(num, pubkey1_bytes, pubkey2_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _point_loop_addition(num, pubkey1_bytes, pubkey2_bytes):
    res = (b'\x00') * (65 * num)
    ice.point_loop_addition(num, pubkey1_bytes, pubkey2_bytes, res)
    return res
def point_loop_addition(num, pubkey1_bytes, pubkey2_bytes):
    if num <= 0: num = 1
    res = _point_loop_addition(num, pubkey1_bytes, pubkey2_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _point_vector_addition(num, pubkeys1_bytes, pubkeys2_bytes):
    res = (b'\x00') * (65 * num)
    ice.point_vector_addition(num, pubkeys1_bytes, pubkeys2_bytes, res)
    return res
def point_vector_addition(num, pubkeys1_bytes, pubkeys2_bytes):
    if num <= 0: num = 1
    res = _point_vector_addition(num, pubkeys1_bytes, pubkeys2_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _point_sequential_increment(num, pubkey1_bytes):
    res = (b'\x00') * (65 * num)
    ice.point_sequential_increment(num, pubkey1_bytes, res)
    return res
def point_sequential_increment(num, pubkey1_bytes):
    ''' This is the fastest implementation.
    Remember, DONT use it to increment from very initial values of pubkey1 example 1 to 500.
    The results are valid if the pubkey1_bytes are corresponding to the pvk > num.
    For those inital values a slighly slower, point_loop_addition can be used.'''
    if num <= 0: num = 1
    res = _point_sequential_increment(num, pubkey1_bytes)
    return bytes(bytearray(res))
#==============================================================================
def pubkey_to_ETH_address(pubkey_bytes):
    ''' 65 Upub bytes input. Output is 20 bytes ETH address lowercase with 0x'''
    xy = pubkey_bytes[1:]
    res = ice.pubkeyxy_to_ETH_address(xy)
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return '0x'+addr
#==============================================================================
def privatekey_to_ETH_address(pvk_int):
    ''' Privatekey Integer value passed to function. Output is 20 bytes ETH address lowercase with 0x'''
    if pvk_int < 0: pvk_int = N+pvk_int
    pass_int_value = hex(pvk_int)[2:].encode('utf8')
    res = ice.privatekey_to_ETH_address(pass_int_value)
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return '0x'+addr
#==============================================================================
def privatekey_group_to_ETH_address(pvk_int, m):
    ''' Starting Privatekey Integer value passed to function as pvk_int.
    Integer m is, how many times sequential increment is done from the starting key.
    Output is bytes 20*m of ETH address lowercase without 0x'''
    if m<=0: m = 1
    if pvk_int < 0: pvk_int = N+pvk_int
    start_pvk = hex(pvk_int)[2:].encode('utf8')
    res = ice.privatekey_group_to_ETH_address(start_pvk, m)
    addrlist = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addrlist
#==============================================================================

        