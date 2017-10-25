#!/usr/bin/env python
from __future__ import print_function
import binascii, os
import jmbitcoin as btc
from ecies import encrypt_message, decrypt_message

def test_encrypt_decrypt():
    bob_privkey = binascii.hexlify(os.urandom(32)) + "01"
    bob_pubkey = btc.privkey_to_pubkey(bob_privkey)
    print("encrypting to bob's public key: " , bob_pubkey)
    alicemsg = "hello, no cigar, but some beer, and here is some more text."
    encrypted = encrypt_message(alicemsg, bob_pubkey)
    print(encrypted)
    decrypted = decrypt_message(encrypted, bob_privkey)
    print(decrypted)
    return alicemsg == decrypted


if __name__ == "__main__":
    if not test_encrypt_decrypt():
        print("Failed")
        exit(1)
    else:
        print("Success")
