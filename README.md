# SNICKER-POC
Simple non-interactive coinjoin with keys for encryption reused; proof of concept

For a description of the idea, see [here](https://gist.github.com/AdamISZ/8dc3bbb00ac33e270029fe1cdb52f3f4).

First, this is a work in progress and only a simple implementation/POC.

Second, **ON NO ACCOUNT USE THIS WITH REAL MONEY YET!!**.

This repo will contain very basic tooling to allow a user to either:

* Propose a coinjoin, using an existing utxo with a reused key/address
they found via another method.

* Take a list of encrypted SNICKER messages and identify which ones can be used,
then decrypt those in full to find partially signed coinjoins, and then present
to the user, who can choose to complete the signing and broadcast them.

### Requirements

For my own ease of development this has been built using https://github.com/Joinmarket-Org/joinmarket-clientserver. This can be installed
by using the install script instructions in that repo's README.

This should be fairly painless on Debian/Ubuntu, and is by some accounts possible on other distros including Mac. But not Windows.

I may later investigate (a) how to create a workflow using Electrum and/or Core with manual steps,
which is going to be desirable for experimenters who don't want to bother setting up a Joinmarket
wallet, and (b) an easy way to integrate this into another wallet architecture.


### Usage

Currently you can follow this workflow, on regtest/testnet, will flesh out as it develops:

* Install joinmarket-clientserver from [here](https://github.com/Joinmarket-Org/joinmarket-clientserver),
using the install script for simplicity (although it will install stuff you don't need like twisted).
* Enter the virtualenv as per the instructions there.
* Find a set of data (utxo, pubkey, amount) from somewhere on the blockchain. Format of utxo is `txid:N` and of pubkey is hex compressed (i.e. starts with 02 or 03, 66 characters).
Note as per the gist mentioned at the start, you need a reused address for this. It has to be
p2pkh or p2sh/p2wpkh (maybe native p2wpkh works too, haven't thought about it).
* Create or load the joinmarket wallet; you can use `python wallet-tool.py` in your joinmarket-clientsever installation.
* The wallet will have to contain at least one utxo that is larger than the amount you found on the blockchain
in the above step. (VERY SIMPLE for now! Only one utxo from each party). Note the mixdepth that utxo is in.
* Run in this repo `python snicker-tool.py -m mixdepth wallet-name utxo pubkey amount` where `amount` is the amount
you recorded from the blockchain before, and is an integer in satoshis.
* It should output a base64 encoded message which contains the transaction, partially signed with your utxo.
* Assuming you know the other party that owns the utxo you found you can send them this partially signed
transaction and they can complete the signing and broadcast.



