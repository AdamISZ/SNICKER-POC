from __future__ import print_function
import hmac
import hashlib
import binascii
import base64
import os
import jmbitcoin as btc
from .slowaes import encryptData, decryptData

#Attribution: this is adapted from
#https://github.com/spesmilo/electrum/blob/master/lib/bitcoin.py
#(although using different crypto libraries)
#In particular, it shares the same ciphertext magic bytes, so messages
#will be decryptable in Electrum (UPDATE: not quite; IV is done differently,
#I can hack this to be compatible later TODO)
#Thus the following copied note applies:
#
#ECIES encryption/decryption methods;
#AES-128-CBC with PKCS7 is used as the cipher;
#hmac-sha256 is used as the mac

def encrypt_message(message, pubkey_hex):
    alice_r = binascii.hexlify(os.urandom(32))
    alice_R = btc.privkey_to_pubkey(alice_r + "01") #use compression flag for pubkey
    ecdh_key = btc.multiply(alice_r, pubkey_hex, True,
                            rawpub=True, return_serialized=True)
    key = hashlib.sha512(ecdh_key).digest()
    key_e, key_m = key[0:16], key[16:]
    ciphertext = encryptData(key_e, message)
    encrypted = b'BIE1' + binascii.unhexlify(alice_R) + ciphertext
    mac = hmac.new(key_m, encrypted, hashlib.sha256).digest()

    return base64.b64encode(encrypted + mac)

def decrypt_message(encrypted, privkey):
    encrypted = base64.b64decode(encrypted)
    if len(encrypted) < 85:
        raise Exception('invalid ciphertext: length')
    magic = encrypted[:4]
    ephemeral_pubkey = binascii.hexlify(encrypted[4:37])
    print("Using ephemeral pubkey from ctrprty: ", ephemeral_pubkey)
    ciphertext = encrypted[37:-32]
    mac = encrypted[-32:]
    if magic != b'BIE1':
        raise Exception('invalid ciphertext: invalid magic bytes')
    ecdh_key = btc.multiply(privkey[:64], ephemeral_pubkey, True,
                            rawpub=True, return_serialized=True)
    key = hashlib.sha512(ecdh_key).digest()
    key_e, key_m = key[0:16], key[16:]
    if mac != hmac.new(key_m, encrypted[:-32], hashlib.sha256).digest():
        raise Exception("ciphertext is not authenticated")
    return decryptData(key_e, ciphertext)

