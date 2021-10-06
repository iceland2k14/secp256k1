# -*- coding: utf-8 -*-
"""

@author: iceland
"""

import platform
import os
import sys
import ctypes


###############################################################################
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


ice.scalar_multiplication.argtypes = [ctypes.c_char_p, ctypes.c_char_p]            # pvk,ret
#==============================================================================
ice.point_increment.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p] # x,y,ret
#==============================================================================
ice.point_negation.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]  # x,y,ret
#==============================================================================
ice.point_doubling.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]  # x,y,ret
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
ice.create_baby_table.argtypes = [ctypes.c_ulonglong, ctypes.c_ulonglong, ctypes.c_char_p] # start,end,ret
#==============================================================================
ice.point_addition.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p] # x1,y1,x2,y2,ret
#==============================================================================
ice.point_subtraction.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p] # x1,y1,x2,y2,ret
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


def _scalar_multiplication(kk):
    ''' Integer value passed to function. 65 bytes uncompressed pubkey output '''
    res = (b'\x00') * 65
    pass_int_value = hex(kk)[2:].encode('utf8')
    ice.scalar_multiplication(pass_int_value, res)
    return res
def scalar_multiplication(kk):
    res = _scalar_multiplication(kk)
    return bytes(bytearray(res))
#==============================================================================
def _point_increment(pubkey_bytes):
    x1 = pubkey_bytes[1:33]
    y1 = pubkey_bytes[33:]
    res = (b'\x00') * 65
    ice.point_increment(x1, y1, res)
    return res
def point_increment(pubkey_bytes):
    res = _point_increment(pubkey_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _point_negation(pubkey_bytes):
    x1 = pubkey_bytes[1:33]
    y1 = pubkey_bytes[33:]
    res = (b'\x00') * 65
    ice.point_negation(x1, y1, res)
    return res
def point_negation(pubkey_bytes):
    res = _point_negation(pubkey_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _point_doubling(pubkey_bytes):
    x1 = pubkey_bytes[1:33]
    y1 = pubkey_bytes[33:]
    res = (b'\x00') * 65
    ice.point_doubling(x1, y1, res)
    return res
def point_doubling(pubkey_bytes):
    res = _point_doubling(pubkey_bytes)
    return bytes(bytearray(res))
#==============================================================================
def privatekey_to_coinaddress(coin_type, addr_type, iscompressed, pvk_int):
    # type = 0 [p2pkh],  1 [p2sh],  2 [bech32]
    pass_int_value = hex(pvk_int)[2:].encode('utf8')
    res = ice.privatekey_to_coinaddress(coin_type, addr_type, iscompressed, pass_int_value)
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addr
#==============================================================================
def privatekey_to_address(addr_type, iscompressed, pvk_int):
    # type = 0 [p2pkh],  1 [p2sh],  2 [bech32]
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
    pass_int_value = hex(pvk_int)[2:].encode('utf8')
    res = (b'\x00') * (20 * num)
    ice.privatekey_loop_h160(num, addr_type, iscompressed, pass_int_value, res)
    return res
def privatekey_loop_h160(num, addr_type, iscompressed, pvk_int):
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
def pbkdf2_hmac_sha512_dll(words):
    seed_bytes = (b'\x00') * 64
#    words = 'good push broken people salad bar mad squirrel joy dismiss merge jeans token wear boring manual doll near sniff turtle sunset lend invest foil'
    ice.pbkdf2_hmac_sha512_dll(seed_bytes, words.encode("utf-8"), len(words))
    return seed_bytes
#==============================================================================
def create_baby_table(start_value, end_value):
    res = (b'\x00') * ((1+end_value-start_value) * 32)
    ice.create_baby_table(start_value, end_value, res)
    return res
#==============================================================================
def _point_addition(pubkey1_bytes, pubkey2_bytes):
    x1 = pubkey1_bytes[1:33]
    y1 = pubkey1_bytes[33:]
    x2 = pubkey2_bytes[1:33]
    y2 = pubkey2_bytes[33:]
    res = (b'\x00') * 65
    ice.point_addition(x1, y1, x2, y2, res)
    return res
def point_addition(pubkey1_bytes, pubkey2_bytes):
    res = _point_addition(pubkey1_bytes, pubkey2_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _point_subtraction(pubkey1_bytes, pubkey2_bytes):
    x1 = pubkey1_bytes[1:33]
    y1 = pubkey1_bytes[33:]
    x2 = pubkey2_bytes[1:33]
    y2 = pubkey2_bytes[33:]
    res = (b'\x00') * 65
    ice.point_subtraction(x1, y1, x2, y2, res)
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
    res = _point_loop_subtraction(num, pubkey1_bytes, pubkey2_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _point_loop_addition(num, pubkey1_bytes, pubkey2_bytes):
    res = (b'\x00') * (65 * num)
    ice.point_loop_addition(num, pubkey1_bytes, pubkey2_bytes, res)
    return res
def point_loop_addition(num, pubkey1_bytes, pubkey2_bytes):
    res = _point_loop_addition(num, pubkey1_bytes, pubkey2_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _point_vector_addition(num, pubkeys1_bytes, pubkeys2_bytes):
    res = (b'\x00') * (65 * num)
    ice.point_vector_addition(num, pubkeys1_bytes, pubkeys2_bytes, res)
    return res
def point_vector_addition(num, pubkeys1_bytes, pubkeys2_bytes):
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
    start_pvk = hex(pvk_int)[2:].encode('utf8')
    res = ice.privatekey_group_to_ETH_address(start_pvk, m)
    addrlist = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addrlist
#==============================================================================
###############################################################################
