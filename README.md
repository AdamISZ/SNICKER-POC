# SNICKER-POC
Simple non-interactive coinjoin with keys for encryption reused; proof of concept

For a description of the idea, see [here](https://gist.github.com/AdamISZ/8dc3bbb00ac33e270029fe1cdb52f3f4).

First, this is a work in progress and only a simple implementation/POC.

Second, **ON NO ACCOUNT USE THIS WITH REAL MONEY YET!!**.

This repo will contain very basic tooling to allow a user to either:

* Propose a coinjoin, using an existing utxo with a reused key/address
they found via another method.

* Take a list of encrypted SNICKER messages and identify which ones can be used,
for a particular provided keypair (you must provide the private key in order to
decrypt the message), then decrypt those in full to find partially signed
coinjoins, and then present to the user, who can choose to complete the signing
and broadcast them.


### Requirements

For my own ease of development this has been built using [Joinmarket-clientserver](https://github.com/Joinmarket-Org/joinmarket-clientserver).
This can be installed by using the install script instructions in that repo's README.

This should be fairly painless on Debian/Ubuntu, and is by some accounts possible
on other distros including Mac. But not Windows.

I (or others) may later investigate (a) how to create a workflow using Electrum
and/or Core with manual steps, which is going to be desirable for experimenters
who don't want to bother setting up a Joinmarket wallet, and (b) an easy way to
integrate this into another wallet architecture.

See notes at the end about possibilities/difficulties for using Core or Electrum.

### Usage

This workflow is using Joinmarket-clientserver (mainly, its underlying Bitcoin library).
Parts can already be done in Electrum and/or Core, as noted below, especially
receiver-side. That will be expanded at the end of this section; for now we assume
Joinmarket:

##### Preparatory step

* Clone this repo.
* Install joinmarket-clientserver from [here](https://github.com/Joinmarket-Org/joinmarket-clientserver),
using the install script for simplicity (although it will install stuff you don't
need like twisted).
* Enter the virtualenv as per the instructions there.

##### Step 0 - only for testing, in absence of scanning blockchain for pubkeys or just for convenience of testers:

* Generate a joinmarket wallet with `python wallet-tool.py generate`
* Pay coins into it; see TESTING.md in docs/ in joinmarket-clientserver for some
notes on a convenient way to arrange this on regtest; on testnet just get an address
from the wallet with `python wallet-tool.py --fast walletname` and pay into it.
* In this testing scenario there is no need to create a "reused key" (you're going to
manually transfer the pubkey so you don't need to).
* You need to note the utxo, the pubkey and the amount. The utxo can be found with
`python wallet-tool.py --fast walletname showutxos`, which will also show you the amount
and the address. To get the pubkey you can run `python snicker-tool.py --fast -p walletname address`.
The pubkey will be 66 characters starting with '03' or '02'.
* With this information (utxo, pubkey, amount) in hand we can move to the "creator",
or "Alice" side (this can be you or someone else if two people are testing). Pass
that info across.

##### Step 1 - Creation/proposal workflow

* The creator also needs a Joinmarket wallet, so creates just as above if necessary.
That wallet needs at least 1 utxo with an amount greater than the amount noted above
(this is a silly restriction which can/will be changed in the code soon fairly easily),
usually that will be in mixdepth 0, but in any case note the mixdepth.
* The creator runs `python snicker-tool.py --fast -m mixdepth walletfile utxo pubkey amount`
* It should output a base64 encoded and ECIES encrypted message which contains the
transaction, partially signed with your utxo.
* Pass this to the other party (in real use you will broadcast this
encrypted message instead).

##### Step 2 - Receiver workflow

* To decrypt it they need their private key. They can get it with `python wallet-tool.py -p walletfile`,
and note the privkey (WIF compressed) next to the first address they deposited into.
* Now they (or you in testing) can run `python snicker-tool.py -r filename` where
`filename` is a file containing the encrypted message (or more than one,
line separated). They will be prompted to enter the WIF compressed privkey, and the
amount in satoshis (this is the amount from the start). If it works, a txt file
will be created containing the hex-encoded partially signed transaction, and other
information, most crucially the WIF compressed privkey of the output destination for
the receiver (this is an output privkey/address specially created with the tweak,
it is not recorded anywhere else so they need to not lose this if they want to keep
the coins).
* To sign and broadcast the transaction, the receiver does `python snicker-tool.py --fast -b walletname fully-signed-tx-hex`
where the last argument is copied from the .txt file. Assuming all OK and they accept, it will be broadcast to the network.

##### Receiving workflow if not using Joinmarket?

There are three basic steps to the receiver workflow: (1) decrypt the message that
is base64 encoded and ECIES encrypted to their pubkey, (2) Calculate and store
the tweaked private key of the output that the receiver owns, and (3) Complete the signing of
the utxo and broadcast it to the network (after sanity checking the tx, of course).
(3) is easily achieved with Bitcoin Core, if the private key of the input is in the
Bitcoin Core wallet; just directly pass the partially signed txhex to `signrawtransaction`,
and use the result as argument to `sendrawtransaction`. This has been verified to work.
The problem is the decryption and tweaked key calculation steps, (1),(2):
the decryption can be done in Electrum, but Electrum needs to "own" the private key
of the pubkey the message was encrypted to. Presumably this can be achieved by
importing the key from Core into Electrum, if necessary. But note the message is in binary in a specific
format and you would at least need to record the 32 byte "tweak" which occurs after
the magic and version bytes, and before the serialized transaction.

To do the entirety of the receiver side in Electrum may be possible, although
I haven't tried it yet. The stumbling blocks are above. If you want to get clever
about it or experiment, do so on testnet. So to summarize the issues: what is
blocking *really* easy integration into an existing wallet is the calculation of
the tweaked output, and the ECIES decryption (although the latter can be farmed out to Electrum with a very
trivial conversion to take the output from that and parse it).



