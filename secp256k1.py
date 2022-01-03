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
ice.scalar_multiplication.argtypes = [ctypes.c_char_p, ctypes.c_char_p]   # pvk,ret
#==============================================================================
# ice.scalar_multiplications.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p]  # pvk,len,ret
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
ice.privatekey_loop_h160_sse.argtypes = [ctypes.c_ulonglong, ctypes.c_int, ctypes.c_bool, ctypes.c_char_p, ctypes.c_char_p]  # num,012,comp,pvk,ret
#==============================================================================
ice.pubkey_to_h160.argtypes = [ctypes.c_int, ctypes.c_bool, ctypes.c_char_p, ctypes.c_char_p]  # 012,comp,upub,ret
#==============================================================================
ice.pbkdf2_hmac_sha512_dll.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int] # ret, words, len
#==============================================================================
ice.pbkdf2_hmac_sha512_list.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_int, ctypes.c_ulonglong] # ret,words,len,mnem_size,total 
#==============================================================================
ice.pub_endo1.argtypes = [ctypes.c_char_p, ctypes.c_char_p]  # upub,ret
#==============================================================================
ice.pub_endo2.argtypes = [ctypes.c_char_p, ctypes.c_char_p]  # upub,ret
#==============================================================================
ice.b58_encode.argtypes = [ctypes.c_char_p]  # _h
ice.b58_encode.restype = ctypes.c_void_p
#==============================================================================
ice.b58_decode.argtypes = [ctypes.c_char_p]  # addr
ice.b58_decode.restype = ctypes.c_void_p
#==============================================================================
ice.bech32_address_decode.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]  # coin,b32_addr,h160
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
ice.point_sequential_increment_P2.argtypes = [ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p] # num,upub1,ret
#==============================================================================
ice.point_sequential_increment_P2_mcpu.argtypes = [ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p] # num,upub1,mcpu,ret
#==============================================================================
ice.point_sequential_increment.argtypes = [ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p] # num,upub1,ret
#==============================================================================
ice.point_sequential_decrement.argtypes = [ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p] # num,upub1,ret
#==============================================================================
ice.pubkeyxy_to_ETH_address.argtypes = [ctypes.c_char_p] # upub_xy
ice.pubkeyxy_to_ETH_address.restype = ctypes.c_void_p
#==============================================================================
ice.pubkeyxy_to_ETH_address_bytes.argtypes = [ctypes.c_char_p, ctypes.c_char_p] # upub_xy, ret
#==============================================================================
ice.privatekey_to_ETH_address.argtypes = [ctypes.c_char_p] # pvk
ice.privatekey_to_ETH_address.restype = ctypes.c_void_p
#==============================================================================
ice.privatekey_to_ETH_address_bytes.argtypes = [ctypes.c_char_p, ctypes.c_char_p] # pvk, ret
#==============================================================================
ice.privatekey_group_to_ETH_address.argtypes = [ctypes.c_char_p, ctypes.c_int] # pvk, m
ice.privatekey_group_to_ETH_address.restype = ctypes.c_void_p
#==============================================================================
ice.privatekey_group_to_ETH_address_bytes.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p] # pvk,m,ret
#==============================================================================
ice.init_P2_Group.argtypes = [ctypes.c_char_p] # upub
#==============================================================================
ice.free_memory.argtypes = [ctypes.c_void_p] # pointer
#==============================================================================
ice.bloom_check_add.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_ulonglong, ctypes.c_ubyte, ctypes.c_char_p] #buff, len, 0_1, _bits, _hashes, _bf
ice.bloom_check_add.restype = ctypes.c_int
#==============================================================================
ice.bloom_batch_add.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_ulonglong, ctypes.c_ubyte, ctypes.c_char_p] #chunk, buff, len, 0_1, _bits, _hashes, _bf
#==============================================================================
ice.test_bit_set_bit.argtypes = [ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_int] #_bf, _bits, 0_1

ice.init_secp256_lib()
#==============================================================================
###############################################################################


def version():
    ice.version()   
#==============================================================================
def _scalar_multiplication(pvk_int):
    ''' Integer value passed to function. 65 bytes uncompressed pubkey output '''
    res = (b'\x00') * 65
    pass_int_value = fl(pvk_int).encode('utf8')
    ice.scalar_multiplication(pass_int_value, res)
    return res
def scalar_multiplication(pvk_int):
    if pvk_int < 0: pvk_int = N+pvk_int
    res = _scalar_multiplication(pvk_int)
    return bytes(bytearray(res))
#==============================================================================
# =============================================================================
# def _scalar_multiplications(pvk_int_list):
#     ''' Integer list passed to function. 65*len bytes uncompressed pubkey output. No Zero Point handling '''
#     sz = len(pvk_int_list)
#     res = (b'\x00') * (65 * sz)
#     pvks = ''.join(pvk_int_list).encode('utf8')
#     ice.scalar_multiplications(pvks, sz, res)
#     return res
# def scalar_multiplications(pvk_int_list):
#     pvk_int_list = [fl(N+i) if i < 0 else fl(i) for i in pvk_int_list]
#     res = _scalar_multiplications(pvk_int_list)
#     return bytes(bytearray(res))
# =============================================================================
#==============================================================================
def point_multiplication(k, P):
    ''' k=scalar. P = Input Point. Output is 65 bytes uncompressed pubkey '''
    if type(P) == int: k,P = P,k
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
def init_P2_Group(pubkey_bytes):
    ice.init_P2_Group(pubkey_bytes)
#==============================================================================
def privatekey_to_coinaddress(coin_type, addr_type, iscompressed, pvk_int):
    # type = 0 [p2pkh],  1 [p2sh],  2 [bech32]
    if pvk_int < 0: pvk_int = N+pvk_int
    pass_int_value = fl(pvk_int).encode('utf8')
    res = ice.privatekey_to_coinaddress(coin_type, addr_type, iscompressed, pass_int_value)
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addr
#==============================================================================
def privatekey_to_address(addr_type, iscompressed, pvk_int):
    # type = 0 [p2pkh],  1 [p2sh],  2 [bech32]
    if pvk_int < 0: pvk_int = N+pvk_int
    pass_int_value = fl(pvk_int).encode('utf8')
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
    pass_int_value = fl(pvk_int).encode('utf8')
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
    pass_int_value = fl(pvk_int).encode('utf8')
    res = (b'\x00') * (20 * num)
    ice.privatekey_loop_h160(num, addr_type, iscompressed, pass_int_value, res)
    return res
def privatekey_loop_h160(num, addr_type, iscompressed, pvk_int):
    if num <= 0: num = 1
    res = _privatekey_loop_h160(num, addr_type, iscompressed, pvk_int)
    return bytes(bytearray(res))
#==============================================================================
def _privatekey_loop_h160_sse(num, addr_type, iscompressed, pvk_int):
    # type = 0 [p2pkh],  1 [p2sh],  2 [bech32]
    if pvk_int < 0: pvk_int = N+pvk_int
    pass_int_value = fl(pvk_int).encode('utf8')
    res = (b'\x00') * (20 * num)
    ice.privatekey_loop_h160_sse(num, addr_type, iscompressed, pass_int_value, res)
    return res
def privatekey_loop_h160_sse(num, addr_type, iscompressed, pvk_int):
    if num <= 0: num = 1
    res = _privatekey_loop_h160_sse(num, addr_type, iscompressed, pvk_int)
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
def b58py(data):
    B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    if data[0] == 0:
        return "1" + b58py(data[1:])

    x = sum([v * (256 ** i) for i, v in enumerate(data[::-1])])
    ret = ""
    while x > 0:
        ret = B58[x % 58] + ret
        x = x // 58
        
    return ret
#==============================================================================
def b58_encode(inp_bytes):
    res = ice.b58_encode(inp_bytes, len(inp_bytes))
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addr
#==============================================================================
def b58_decode(inp):
    res = ice.b58_decode(inp.encode("utf-8"))
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addr
#==============================================================================
def bech32_address_decode(addr, coin_type=0):
    ''' Input address in String format. Output h160 in hex string format
    [Note] p2wsh = bech32(sha256(21 + pubkey + ac)). So Decoding it not Needed '''
    if len(addr) > 50: print('[Error] Bech32 p2wsh Not Supported. Result Truncated')
    h160 = (b'\x00') * 20
    ice.bech32_address_decode(coin_type, addr.encode("utf-8"), h160)
    return bytes(bytearray(h160)).hex()
#==============================================================================
def address_to_h160(p2pkh):
    ''' Input address in String format. Output h160 in hex string format'''
    h1 = b58_decode(p2pkh)
    return h1[2:-8]
#==============================================================================
def btc_wif_to_pvk_hex(wif):
    pvk = ''
    if wif[0] == '5':
        pvk = b58_decode(wif)[2:-8]
    elif wif[0] in ['L', 'K']:
        pvk = b58_decode(wif)[2:-10]
    else: print('[Error] Incorrect WIF Key')
    return pvk
#==============================================================================
def btc_wif_to_pvk_int(wif):
    pvk = ''
    pvk_hex = btc_wif_to_pvk_hex(wif)
    if pvk_hex != '': pvk = int(pvk_hex, 16)
    return pvk
#==============================================================================
def btc_pvk_to_wif(pvk, is_compressed=True):
    ''' Input Privatekey can in any 1 of these [Integer] [Hex] [Bytes] form'''
    inp = ''
    suff = '01' if is_compressed == True else ''
    if type(pvk) in [int, str]: inp = bytes.fromhex('80' + fl(pvk) + suff)
    elif type(pvk) == bytes: inp = b'\x80' + fl(pvk) + bytes.fromhex(suff)
    else: print("[Error] Input Privatekey format [Integer] [Hex] [Bytes] allowed only")
    if inp != '':
        res = get_sha256(inp)
        res2 = get_sha256(res)
        return b58_encode(inp + res2[:4])
    else: return inp
#==============================================================================
def fl(sstr, length=64):
    ''' Fill input to exact 32 bytes. If input is int or str the return is str. if input is bytes return is bytes'''
    if type(sstr) == int: fixed = hex(sstr)[2:].zfill(length)
    elif type(sstr) == str: fixed = sstr[2:].zfill(length) if sstr[:2].lower() == '0x' else sstr.zfill(length)
    elif type(sstr) == bytes: fixed = (b'\x00') * (32 - len(sstr)) + sstr
    else: print("[Error] Input format [Integer] [Hex] [Bytes] allowed only")
    return fixed
#==============================================================================
def pbkdf2_hmac_sha512_dll(words):
    seed_bytes = (b'\x00') * 64
#    words = 'good push broken people salad bar mad squirrel joy dismiss merge jeans token wear boring manual doll near sniff turtle sunset lend invest foil'
    ice.pbkdf2_hmac_sha512_dll(seed_bytes, words.encode("utf-8"), len(words))
    return seed_bytes
#==============================================================================
def pbkdf2_hmac_sha512_list(words_list):
    ''' strength is [12, 18, 24]. words_list is a list of strings with each line having valid mnemonics'''
    wl = len(words_list)
    strength = len(words_list[0].split())
    words = ' '.join(words_list)
    seed_bytes = (b'\x00') * (64 * wl)
#    words = 'good push broken people salad bar mad squirrel joy dismiss merge jeans token wear boring manual doll near sniff turtle sunset lend invest foil'
    ice.pbkdf2_hmac_sha512_list(seed_bytes, words.encode("utf-8"), len(words), strength, wl)
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
    ''' Continuously subtracting point2 into point1 in a loop of num times. 
    Output is array of pubkeys P1-P2, P1-2P2, P1-3P2, P1-4P2....'''
    if num <= 0: num = 1
    res = _point_loop_subtraction(num, pubkey1_bytes, pubkey2_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _point_loop_addition(num, pubkey1_bytes, pubkey2_bytes):
    res = (b'\x00') * (65 * num)
    ice.point_loop_addition(num, pubkey1_bytes, pubkey2_bytes, res)
    return res
def point_loop_addition(num, pubkey1_bytes, pubkey2_bytes):
    ''' Continuously adding point2 into point1 in a loop of num times. 
    Output is array of pubkeys P1+P2, P1+2P2, P1+3P2, P1+4P2....'''
    if num <= 0: num = 1
    res = _point_loop_addition(num, pubkey1_bytes, pubkey2_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _point_vector_addition(num, pubkeys1_bytes, pubkeys2_bytes):
    res = (b'\x00') * (65 * num)
    ice.point_vector_addition(num, pubkeys1_bytes, pubkeys2_bytes, res)
    return res
def point_vector_addition(num, pubkeys1_bytes, pubkeys2_bytes):
    ''' Adding two array of points of equal length. '''
    if num <= 0: num = 1
    res = _point_vector_addition(num, pubkeys1_bytes, pubkeys2_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _point_sequential_increment_P2(num, pubkey1_bytes):
    res = (b'\x00') * (65 * num)
    ice.point_sequential_increment_P2(num, pubkey1_bytes, res)
    return res
def point_sequential_increment_P2(num, pubkey1_bytes):
    ''' This is the fastest implementation to add point P2 in the given Point sequentially.'''
    if num <= 0: num = 1
    res = _point_sequential_increment_P2(num, pubkey1_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _point_sequential_increment_P2_mcpu(num, pubkey1_bytes, mcpu):
    res = (b'\x00') * (65 * num)
    ice.point_sequential_increment_P2_mcpu(num, pubkey1_bytes, mcpu, res)
    return res
def point_sequential_increment_P2_mcpu(num, pubkey1_bytes, mcpu=os.cpu_count()):
    ''' This is the fastest multi CPU implementation to add point P2 in the given Point sequentially. Threads are Not optimised yet'''
    if num <= 0: num = 1
    res = _point_sequential_increment_P2_mcpu(num, pubkey1_bytes, mcpu)
    return bytes(bytearray(res))
#==============================================================================
def _point_sequential_increment(num, pubkey1_bytes):
    res = (b'\x00') * (65 * num)
    ice.point_sequential_increment(num, pubkey1_bytes, res)
    return res
def point_sequential_increment(num, pubkey1_bytes):
    ''' This is the fastest implementation using G'''
    if num <= 0: num = 1
    res = _point_sequential_increment(num, pubkey1_bytes)
    return bytes(bytearray(res))
#==============================================================================
def _point_sequential_decrement(num, pubkey1_bytes):
    res = (b'\x00') * (65 * num)
    ice.point_sequential_decrement(num, pubkey1_bytes, res)
    return res
def point_sequential_decrement(num, pubkey1_bytes):
    ''' This is the fastest implementation using -G.'''
    if num <= 0: num = 1
    res = _point_sequential_decrement(num, pubkey1_bytes)
    return bytes(bytearray(res))
#==============================================================================
def pubkey_to_ETH_address(pubkey_bytes):
    ''' 65 Upub bytes input. Output is 20 bytes ETH address lowercase with 0x as hex string'''
    xy = pubkey_bytes[1:]
    res = ice.pubkeyxy_to_ETH_address(xy)
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return '0x'+addr
#==============================================================================
def _pubkey_to_ETH_address_bytes(xy):
    res = (b'\x00') * 20
    ice.pubkeyxy_to_ETH_address_bytes(xy, res)
    return res
def pubkey_to_ETH_address_bytes(pubkey_bytes):
    ''' 65 Upub bytes input. Output is 20 bytes ETH address lowercase without 0x'''
    xy = pubkey_bytes[1:]
    res = _pubkey_to_ETH_address_bytes(xy)
    return bytes(bytearray(res))
#==============================================================================
def privatekey_to_ETH_address(pvk_int):
    ''' Privatekey Integer value passed to function. Output is 20 bytes ETH address lowercase with 0x as hex string'''
    if pvk_int < 0: pvk_int = N+pvk_int
    pass_int_value = fl(pvk_int).encode('utf8')
    res = ice.privatekey_to_ETH_address(pass_int_value)
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return '0x'+addr
#==============================================================================
def _privatekey_to_ETH_address_bytes(pass_int_value):
    res = (b'\x00') * 20
    ice.privatekey_to_ETH_address_bytes(pass_int_value, res)
    return res
def privatekey_to_ETH_address_bytes(pvk_int):
    ''' Privatekey Integer value passed to function. Output is 20 bytes ETH address lowercase without 0x'''
    if pvk_int < 0: pvk_int = N+pvk_int
    pass_int_value = fl(pvk_int).encode('utf8')
    res = _privatekey_to_ETH_address_bytes(pass_int_value)
    return bytes(bytearray(res))
#==============================================================================
def privatekey_group_to_ETH_address(pvk_int, m):
    ''' Starting Privatekey Integer value passed to function as pvk_int.
    Integer m is, how many times sequential increment is done from the starting key.
    Output is bytes 20*m of ETH address lowercase without 0x as hex string'''
    if m<=0: m = 1
    if pvk_int < 0: pvk_int = N+pvk_int
    start_pvk = fl(pvk_int).encode('utf8')
    res = ice.privatekey_group_to_ETH_address(start_pvk, m)
    addrlist = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addrlist
#==============================================================================
def _privatekey_group_to_ETH_address_bytes(start_pvk, m):
    res = (b'\x00') * (20 * m)
    ice.privatekey_group_to_ETH_address_bytes(start_pvk, m, res)
    return res
def privatekey_group_to_ETH_address_bytes(pvk_int, m):
    ''' Starting Privatekey Integer value passed to function as pvk_int.
    Integer m is, how many times sequential increment is done from the starting key.
    Output is bytes 20*m of ETH address lowercase without 0x'''
    if m<=0: m = 1
    if pvk_int < 0: pvk_int = N+pvk_int
    start_pvk = fl(pvk_int).encode('utf8')
    res = _privatekey_group_to_ETH_address_bytes(start_pvk, m)
    return bytes(bytearray(res))
#==============================================================================