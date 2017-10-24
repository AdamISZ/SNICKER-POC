#!/usr/bin/env python
from __future__ import print_function
import binascii
import os
from optparse import OptionParser
import jmbitcoin as btc
from jmclient import (load_program_config, validate_address, jm_single,
                      WalletError, sync_wallet, RegtestBitcoinCoreInterface,
                      estimate_tx_fee, Wallet, SegwitWallet, get_p2pk_vbyte,
                      get_p2sh_vbyte)
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
        'Parse a list of encrypted messages in the file specified in the '
        'second argument, checking them against the privkey given as first '
        'argument (TODO replace this unsafe thing, its just for testing) '
        ', for any match the decrypted, partially signed transaction '
        'is output, which you can pass to signrawtransaction in bitcoind in '
        'order to broadcast.')
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
        destination_address = btc.pubkey_to_p2sh_p2wpkh_address(destination_point,
                                                                magicbyte=get_p2sh_vbyte())
    else:
        destination_address = btc.pubkey_to_address(destination_point,
                                                    magicbyte=get_p2pk_vbyte())
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
    tweak, dest_pt, bob_destination = create_recipient_address(bob_pubkey, segwit=True)
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

def deserialize_coinjoin_proposal(msg):
    if not msg[:8] == magic_bytes:
        return False
    if not msg[8:10] == version_bytes:
        return False
    tweak = binascii.hexlify(msg[10:42])
    tx = binascii.hexlify(msg[42:])
    return (tweak, tx)

def scan_for_coinjoins(privkey, amount, filename):
    try:
        with open(filename, "rb") as f:
            msgs = f.readlines()
    except:
        print("Failed to read from file: ", filename)
        return
    valid_coinjoins = []
    for msg in msgs:
        try:
            decrypted_msg = decrypt_message(msg, privkey)
            tweak, tx = deserialize_coinjoin_proposal(decrypted_msg)
        except:
            print("Could not decrypt message, skipping")
            continue
        #We analyse the content of the transaction to check if it follows
        #our requirements
        deserialized_tx = btc.deserialize(tx)
        #construct our receiving address according to the tweak
        pubkey = btc.privkey_to_pubkey(privkey)
        tweak, destnpt, my_destn_addr = create_recipient_address(pubkey,
                                                                 tweak=tweak,
                                                                 segwit=True)
        tweak_priv = tweak + "01"
        my_destn_privkey = btc.add_privkeys(tweak_priv, privkey, True)
        print('my destn addr is: ', my_destn_addr)
        print('my destn privkey is: ', my_destn_privkey)
        my_output_index = -1
        for i, o in enumerate(deserialized_tx['outs']):
            try:
                addr = btc.script_to_address(o['script'], get_p2pk_vbyte())
            except:
                addr = btc.script_to_address(o['script'], get_p2sh_vbyte())
            if addr == my_destn_addr:
                print('found our output address: ', my_destn_addr)
                my_output_index = i
                break
            else:
                print('output address was: ', addr)
                print('not ours')
        if my_output_index == -1:
            print("Proposal doesn't contain our output address, rejecting")
            continue
        my_output_amount = deserialized_tx['outs'][i]['value']
        required_amount = amount - 2*estimate_tx_fee(3, 3, 'p2sh-p2wpkh')
        if my_output_amount < required_amount:
            print("Proposal pays too little, difference is: ",
                  required_amount - my_output_amount)
            continue
        #now we know output is acceptable to us, we should check that the
        #ctrprty input is signed and the other input is ours, but will do this
        #later; if it's not, it just won't work so NBD for now.
        valid_coinjoins.append((my_destn_addr, my_destn_privkey, tx))
    return valid_coinjoins

if __name__ == "__main__":
    parser = get_parser()
    (options, args) = parser.parse_args()
    load_program_config()
    if options.receiver:
        privkey, amount, filename = args[:3]
        valid_coinjoins = scan_for_coinjoins(privkey, int(amount), filename)
        if not valid_coinjoins:
            print("Found no valid coinjoins")
            exit(0)
        for vc in valid_coinjoins:
            addr, priv, tx = vc
            print("Found signable coinjoin with destination address: ", addr)
            print("And this private key (p2sh-p2wpkh output): ", priv)
            print("Pass this to signrawtransaction:")
            print(tx)
        exit(0)

    wallet_name, bob_utxo, bob_pubkey, bob_amount = args[:4]
    bob_amount = int(bob_amount)
    #Setup uses joinmarket wallet; this choice is just because it's easier for me.
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

    
    
    