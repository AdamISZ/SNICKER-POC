#!/usr/bin/env python2
from __future__ import print_function
import os
from jmclient import (wallet_tool_main, load_program_config)

if __name__ == "__main__":
    load_program_config()
    #TODO: change this to homedir as in github.com/AdamISZ/CoinSwapCS
    if not os.path.exists('wallets'):
        os.makedirs('wallets')
    print(wallet_tool_main('wallets'))