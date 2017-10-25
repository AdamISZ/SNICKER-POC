#!/usr/bin/env python2
from __future__ import print_function
import binascii, os
import jmbitcoin as btc
from ecies import encrypt_message, decrypt_message

def test_encrypt_decrypt():
    bob_privkey = "02"*32 + "01"
    bob_pubkey = btc.privkey_to_pubkey(bob_privkey)
    print("encrypting to bob's public key: " , bob_pubkey)
    alicemsg = "hello, no cigar, but some beer, and here is some more text."
    encrypted = encrypt_message(alicemsg, bob_pubkey)
    print(encrypted)
    decrypted = decrypt_message(encrypted, bob_privkey)
    print(decrypted)
    return alicemsg == decrypted

def test_decrypt():
    """Can be used for manually testing compatibility;
    shows compatibility with Electrum as of now.
    """
    privkey = raw_input("Enter privkey:")
    print("Got privkey: ", privkey)
    enc_msg = raw_input("Enter encrypted message:")
    print("Got encrypted message: ", enc_msg)
    decrypted = decrypt_message(enc_msg, privkey)
    print("Got decrypted message: ")
    print(decrypted)

def test_encrypt():
    """Comment as for test_decrypt
    """
    pubkey = raw_input("Enter pubkey:")
    msg = raw_input("Enter plaintext:")
    encrypted = encrypt_message(msg, pubkey)
    print("Got encrypted message: ")
    print(encrypted)

if __name__ == "__main__":
    if not test_encrypt_decrypt():
        print("Failed")
        exit(1)
    else:
        print("Success")
