#!/usr/bin/env python2
from __future__ import print_function
import binascii
import os
from optparse import OptionParser
from pprint import pformat
import jmbitcoin as btc
from jmclient import (load_program_config, validate_address, jm_single,
                      WalletError, sync_wallet, RegtestBitcoinCoreInterface,
                      estimate_tx_fee, Wallet, SegwitWallet, get_p2pk_vbyte,
                      get_p2sh_vbyte)
from jmbase.support import get_password
from ecies import encrypt_message, decrypt_message
magic_bytes = "\xa9\x04\x11\xed\xf3\x84\x5a\xaa"
version_bytes = "\x00\x01"

def get_parser():
    parser = OptionParser(
        usage=
        'usage: %prog [options] walletfile utxo pubkey amount\n' + \
        'or: %prog -r file\n' + \
        'or: %prog -b walletfile txhex\n' + \
        'or (testing only): %prog -p walletfile address',
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
        'first argument, checking them against the privkey given by the user '
        'on the command line, in WIF compressed format, and the input amount in '
        'satoshis, for any match. The decrypted, partially signed transaction is '
        'output, assuming the transaction does not lose the user more than a small '
        'fee, and is otherwise valid, which you can pass to signrawtransaction in '
        'Bitcoin Core or similar in order to broadcast.')
    parser.add_option(
        '-b',
        '--broadcast',
        action='store_true',
        dest='broadcast',
        default=False,
        help=
        'Takes a partially signed transaction and completes the signing, only '
        'to be used for a receiver with a Joinmarket wallet. Pass walletfilename '
        'as first argument and partially signed transaction hex (from -r run) '
        'as second argument; you will be prompted whether to broadcast.')
    parser.add_option(
        '-p',
        '--pubkey-only',
        action='store_true',
        dest='pubkey',
        default=False,
        help=
        'Utility for testing only: to pass a pubkey, in a Joinmarket wallet, '
        'across to a counterparty, instead of them having to find it on the '
        'blockchain, use this flag and set the arguments to: walletfile address; '
        'the pubkey for that address will be returned in hex.')
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
    print('here is proposed transaction:\n', pformat(btc.deserialize(unsigned_tx)))
    print('destination for Bob: ', bob_destination)
    print('destination for Alice: ', alice_destination)
    print('destination for Alice change: ', change)
    if not raw_input("Is this acceptable? (y/n):") == "y":
        return (None, None)
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
    """For a specific, already decrypted coinjoin proposal,
    we attempt to decrypt, requiring correct header bytes;
    if there is a failure, we return the reason as the second item,
    and the first as False. If successfully parsed, we return the
    tweak and the bitcoin transaction (serialized) that are embedded.
    Return values are in hex.
    Note that this simple process will be comically slow for parsing
    large numbers of large messages; several mechanisms could improve this,
    e.g. we may need to decrypt only first AES block, checking magic bytes.
    """
    if not msg[:8] == magic_bytes:
        return (False, "Invalid SNICKER magic bytes")
    if not msg[8:10] == version_bytes:
        return (False, "Invalid SNICKER version bytes, should be: " + \
                binascii.hexlify(version_bytes))
    tweak = binascii.hexlify(msg[10:42])
    tx = binascii.hexlify(msg[42:])
    return (tweak, tx)

def scan_for_coinjoins(privkey, amount, filename):
    """Given a file which contains encrypted coinjoin proposals,
    and a private key for a pubkey with a known utxo existing
    which we can spend, scan the entries in the file, all assumed
    to be ECIES encrypted to a pubkey, for one which is encrypted
    to *this* pubkey, if found, output the retrieved partially signed
    transaction, and destination key, address to a list which is
    returned to the caller.
    Only if the retrieved coinjoin transaction passes basic checks
    on validity in terms of amount paid, is it returned.
    This is an elementary implementation that will obviously fail
    any performance test (i.e. moderately large lists).
    Note that the tweaked output address must be of type p2sh/p2wpkh.
    """
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
        if not tweak:
            print("Could not decrypt message, reason: " + str(tx))
            continue
        #We analyse the content of the transaction to check if it follows
        #our requirements
        try:
            deserialized_tx = btc.deserialize(tx)
        except:
            print("Proposed transaction is not correctly formatted, skipping.")
            continue
        #construct our receiving address according to the tweak
        pubkey = btc.privkey_to_pubkey(privkey)
        tweak, destnpt, my_destn_addr = create_recipient_address(pubkey,
                                                                 tweak=tweak,
                                                                 segwit=True)
        #add_privkeys requires both inputs to be compressed (or un-) consistently.
        tweak_priv = tweak + "01"
        my_destn_privkey = btc.add_privkeys(tweak_priv, privkey, True)
        my_output_index = -1
        for i, o in enumerate(deserialized_tx['outs']):
            addr = btc.script_to_address(o['script'], get_p2sh_vbyte())
            if addr == my_destn_addr:
                print('found our output address: ', my_destn_addr)
                my_output_index = i
                break
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

def cli_receive(filename):
    wif_privkey = raw_input("Enter private key in WIF compressed format: ")
    try:
        privkey = btc.from_wif_privkey(wif_privkey, vbyte=get_p2pk_vbyte())
    except:
        print("Could not parse WIF privkey, quitting.")
        return
    amount = raw_input("Enter amount of utxo being spent, in satoshis: ")
    valid_coinjoins = scan_for_coinjoins(privkey, int(amount), filename)
    if not valid_coinjoins:
        print("Found no valid coinjoins")
        return
    for vc in valid_coinjoins:
        addr, priv, tx = vc
        print("Found signable coinjoin with destination address: ", addr)
        #TODO find a more sensible file naming
        fn = btc.txhash(tx)+".txt"
        with open(fn, "wb") as f:
            f.write("SNICKER output file for receiver\n"
                    "================================\n")
            f.write("The serialized transaction in hex:\n")
            f.write(tx + "\n")
            f.write("YOUR DESTINATION: " + addr + "\n")
            f.write("PRIVATE KEY FOR THIS DESTINATION ADDRESS:\n")
            f.write(btc.wif_compressed_privkey(priv, vbyte=get_p2pk_vbyte())+"\n")
            f.write("The decoded transaction:\n")
            f.write(pformat(btc.deserialize(tx))+"\n")
        print("The partially signed transaction and the private key for your "
              "output are stored in the file: " + fn)
        print("Pass the transaction hex to `signrawtransaction` in Bitcoin Core "
              "or similar if you wish to broadcast the transaction.")

def cli_get_wallet(wallet_name, sync=True):
    walletclass = SegwitWallet if jm_single().config.get(
            "POLICY", "segwit") == "true" else Wallet    
    if not os.path.exists(os.path.join('wallets', wallet_name)):
        wallet = walletclass(wallet_name, None, max_mix_depth=options.amtmixdepths)
    else:
        while True:
            try:
                pwd = get_password("Enter wallet decryption passphrase: ")
                wallet = walletclass(wallet_name, pwd, max_mix_depth=options.amtmixdepths)
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
    if sync:
        sync_wallet(wallet, fast=options.fastsync)
    return wallet

def cli_creator(wallet_name, bob_utxo, bob_pubkey, bob_amount):
    """This setup currently uses a joinmarket wallet;
    this choice is just because it's easier for me. Given a
    previously identified (utxo, pubkey, amount) found on the blockchain,
    creates a partially signed coinjoin transaction using a utxo input
    from our own wallet.
    """
    wallet = cli_get_wallet(wallet_name)
    typical_fee = estimate_tx_fee(2, 3, 'p2sh-p2wpkh')
    print('using fee estimate for utxo selection: ', typical_fee)
    #Choose a single utxo sufficient for the required Bob utxo amount.
    chosen_utxo = None
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
    if not tweak:
        print("You aborted the creation of a coinjoin proposal, quitting.")
        exit(0)
    encrypted_message = serialize_coinjoin_proposal(tweak, partially_signed_tx,
                                                    bob_pubkey)
    print("Here is the encrypted message, broadcast it anywhere:")
    print(encrypted_message)

def cli_broadcast(wallet_name, partial_tx_hex):
    """Given a partially signed transaction retrieved by running
    this script with the -r flag, and assuming that the utxo with
    which the transaction was made is in a Joinmarket wallet, this
    function will complete the signing and then broadcast the transaction.
    This function is useful if the *receiver*'s wallet is Joinmarket; if
    it is Core then the workflow is just `signrawtransaction` then
    `sendrawtransaction`; should be similar for Electrum although haven't tried.
    """
    wallet = cli_get_wallet(wallet_name)
    tx = btc.deserialize(partial_tx_hex)
    num_sigs = 0
    for index, ins in enumerate(tx['ins']):
        utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
        #is the utxo in our utxos?
        in_wallet_utxos = wallet.get_utxos_by_mixdepth(False)
        for m, um in in_wallet_utxos.iteritems():
            for k, v in um.iteritems():
                if k == utxo:
                    print("Found utxo in mixdepth: ", m)
                    if isinstance(wallet, SegwitWallet):
                        amount= v['value']
                    else:
                        amount = None
                    signed_tx = btc.sign(partial_tx_hex, index,
                             wallet.get_key_from_addr(v['address']),
                             amount=amount)
                    num_sigs += 1
    if num_sigs != 1:
        print("Something wrong, expected to get 1 sig, got: ", num_sigs)
        return
    #should be fully signed; broadcast?
    print("Signed tx in hex:")
    print(signed_tx)
    print("In decoded form:")
    print(pformat(btc.deserialize(signed_tx)))
    if not raw_input("Broadcast to network? (y/n): ") == "y":
        print("You chose not to broadcast, quitting.")
        return
    txid = btc.txhash(signed_tx)
    print('txid = ' + txid)
    pushed = jm_single().bc_interface.pushtx(signed_tx)
    if not pushed:
        print("Broadcast failed.")
    else:
        print("Broadcast was successful.")

def cli_get_pubkey(wallet_name, address):
    print("Checking for address: ", address)
    wallet = cli_get_wallet(wallet_name)
    privkey = wallet.get_key_from_addr(address)
    pubkey = btc.privkey_to_pubkey(privkey)
    print("Pubkey: ", pubkey)

if __name__ == "__main__":
    parser = get_parser()
    (options, args) = parser.parse_args()
    load_program_config()
    if options.pubkey:
        wallet_name, address = args[:2]
        cli_get_pubkey(wallet_name, address)
        exit(0)
    if options.broadcast:
        wallet_name, partial_tx_hex = args[:2]
        cli_broadcast(wallet_name, partial_tx_hex)
        exit(0)
    if options.receiver:
        filename = args[0]
        cli_receive(filename)
        exit(0)
    wallet_name, bob_utxo, bob_pubkey, bob_amount = args[:4]
    bob_amount = int(bob_amount)
    cli_creator(wallet_name, bob_utxo, bob_pubkey, bob_amount)
    print('done')

    
    
    