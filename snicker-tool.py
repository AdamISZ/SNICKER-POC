#!/usr/bin/env python
from __future__ import print_function
import binascii
import os
from optparse import OptionParser
import jmbitcoin as btc
from jmclient import (load_program_config, validate_address, jm_single,
                      WalletError, sync_wallet, RegtestBitcoinCoreInterface,
                      estimate_tx_fee, Wallet, SegwitWallet)
from jmbase.support import get_log, debug_dump_object, get_password
from ecies import encrypt_message, decrypt_message
magic_bytes = "\xa9\x04\x11\xed\xf3\x84\x5a\xaa"
version_bytes = "\x00\x01"

def get_parser():
    parser = OptionParser(
        usage=
        'usage: %prog [options] walletfile utxo pubkey amount',
        description='Creates an encrypted proposed coinjoin, or completes '
        +
        'signing of a proposed transaction.')
    parser.add_option(
        '-r',
        '--receiver',
        action='store_true',
        dest='receiver',
        default=False,
        help=
        'TODO')
    parser.add_option('-m',
                      '--mixdepth',
                      action='store',
                      type='int',
                      dest='mixdepth',
                      help='mixing depth to choose utxos from, default=0',
                      default=0)
    parser.add_option('-a',
                      '--amtmixdepths',
                      action='store',
                      type='int',
                      dest='amtmixdepths',
                      help='number of mixdepths in wallet, default 5',
                      default=5)
    parser.add_option('-g',
                      '--gap-limit',
                      type="int",
                      action='store',
                      dest='gaplimit',
                      help='gap limit for wallet, default=6',
                      default=6)
    parser.add_option('--fast',
                      action='store_true',
                      dest='fastsync',
                      default=False,
                      help=('choose to do fast wallet sync, only for Core and '
                            'only for previously synced wallet'))
    return parser

def test_encrypt_decrypt():
    bob_privkey = binascii.hexlify(os.urandom(32)) + "01"
    bob_pubkey = btc.privkey_to_pubkey(bob_privkey)
    print("encrypting to bob's public key: " , bob_pubkey)
    alicemsg = "hello, no cigar, but some beer, and here is some more text."
    encrypted = encrypt_message(alicemsg, bob_pubkey)
    print(encrypted)
    raw_input("Enter to continue")
    decrypted = decrypt_message(encrypted, bob_privkey)
    print(decrypted)
    if not alicemsg == decrypted:
        print("Failed")

def create_recipient_address(bob_pubkey, tweak=None, segwit=False):
    """Create a p2pkh receiving address
    from an existing pubkey, tweaked by a random 32 byte scalar.
    Returns the tweak, the new pubkey point and the new address.
    The recipient can set the tweak parameter.
    """
    if not tweak:
        tweak = binascii.hexlify(os.urandom(32))
    tweak_point = btc.privkey_to_pubkey(tweak+"01")
    destination_point = btc.add_pubkeys([tweak_point, bob_pubkey], True)
    if segwit:
        destination_address = btc.pubkey_to_p2sh_p2wpkh_address(destination_point)
    else:
        destination_address = btc.pubkey_to_address(destination_point)
    return (tweak, destination_point, destination_address)
    
def create_coinjoin_proposal(bobdata, alicedata):
    """A very crude/static implementation of a coinjoin for SNICKER.
    **VERY DELIBERATELY STUPIDLY SIMPLE VERSION!**
    We assume only one utxo for each side (this will certainly change, Alice
    side, for flexibility). Two outputs equal size are created with 1 change
    for Alice also (Bob's utxo is completely satisfied by 1 output).
    The data for each side is utxo, and amount; alice must provide
    privkey for partial sign. All scriptpubkeys assumed p2sh/p2wpkh for now.
    Bob's destination is tweaked and included as a destination which he
    will verify.
    What is returned is (tweak, partially signed tx) which is enough information
    for Bob to complete.
    """
    fee = estimate_tx_fee(3, 3, 'p2sh-p2wpkh')
    bob_utxo, bob_pubkey, amount = bobdata
    alice_utxo, alice_privkey, alice_amount, alice_destination, change = alicedata
    ins = [bob_utxo, alice_utxo]
    tweak, dest_pt, bob_destination = create_recipient_address(bob_pubkey)
    coinjoin_amount = amount - int(fee/2)
    change_amount = alice_amount - coinjoin_amount
    outs = [{"address": alice_destination, "value": coinjoin_amount},
            {"address": bob_destination, "value": coinjoin_amount},
            {"address": change, "value": change_amount}]
    unsigned_tx = btc.mktx(ins, outs)
    print('here is proposed transaction', unsigned_tx)
    raw_input()
    #Alice signs her input; assuming segwit here for now
    partially_signed_tx = btc.sign(unsigned_tx, 1, alice_privkey,
                                   amount=alice_amount)
    #return the material to be sent to Bob
    return (tweak, partially_signed_tx)

def serialize_coinjoin_proposal(tweak, transaction, pubkey):
    msg = magic_bytes #8
    msg += version_bytes #2
    msg += binascii.unhexlify(tweak) #32
    msg += binascii.unhexlify(transaction) #variable
    return encrypt_message(msg, pubkey)

if __name__ == "__main__":
    parser = get_parser()
    (options, args) = parser.parse_args()
    wallet_name, bob_utxo, bob_pubkey, bob_amount = args[:4]
    bob_amount = int(bob_amount)
    #Setup uses joinmarket wallet; this choice is just because it's easier for me.
    load_program_config()
    walletclass = SegwitWallet if jm_single().config.get(
            "POLICY", "segwit") == "true" else Wallet    
    if not os.path.exists(os.path.join('wallets', wallet_name)):
        wallet = walletclass(wallet_name, None)
    else:
        while True:
            try:
                pwd = get_password("Enter wallet decryption passphrase: ")
                wallet = walletclass(wallet_name, pwd)
            except WalletError:
                print("Wrong password, try again.")
                continue
            except Exception as e:
                print("Failed to load wallet, error message: " + repr(e))
                sys.exit(0)
            break
    if jm_single().config.get("BLOCKCHAIN",
            "blockchain_source") == "electrum-server":
        jm_single().bc_interface.synctype = "with-script"
    sync_wallet(wallet, fast=options.fastsync)
    print(wallet.unspent)
    typical_fee = estimate_tx_fee(3, 3, 'p2sh-p2wpkh')
    print('using fee estimate for utxo selection: ', typical_fee)
    #Choose a single utxo sufficient for the required Bob utxo amount.
    chosen_utxo = None
    print('ubym', wallet.get_utxos_by_mixdepth(False))
    for k, v in wallet.get_utxos_by_mixdepth(False)[options.mixdepth].iteritems():
        if v['value'] > bob_amount + 2 * typical_fee:
            chosen_utxo = (k, v)
            break
    if not chosen_utxo:
        print("Unable to find a suitable utxo for amount: ", bob_amount)
    #need the private key to sign for this utxo
    privkey = wallet.get_key_from_addr(chosen_utxo[1]['address'])
    #get a destination and a change
    alice_destination = wallet.get_new_addr((
        options.mixdepth+1)% options.amtmixdepths, 1)
    alice_change = wallet.get_new_addr(options.mixdepth, 1)
    bobdata = [bob_utxo, bob_pubkey, bob_amount]
    alicedata = [chosen_utxo[0], privkey, chosen_utxo[1]['value'],
                 alice_destination, alice_change]
    tweak, partially_signed_tx = create_coinjoin_proposal(bobdata, alicedata)
    encrypted_message = serialize_coinjoin_proposal(tweak, partially_signed_tx,
                                                    bob_pubkey)
    print("Here is the encrypted message, broadcast it anywhere:")
    print(encrypted_message)
    print('done')

    
    
    