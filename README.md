# QMiner

Optimised CPU miner for efficient deployment on every device.

- KDB+ is lightweight, cross-platform, independent and the most powerful CPU parallel processing database for mass real-time co-ordinaton.

Why CPU ? - CPU miners are more energy efficient and mass accessible. 

Why co-ordinate ? - Instead of an exponentially increasing hash power competition, we can have an energy efficient co-ordinated effort. i.e. less waste.

What is the incentive ? - Positive incentive feedback structures are important for sustainability and popularity. Here is my proposed structure:

1 % - Who-ever finds the solution for the current block first.

39 % - Split proportionally to the resources dedicated to mining the current block.

30 % - Universal income, claimable daily by low income families accross the planet.

30 % - Earth care trust, claimable by environmental revival projects. 

# Clients
Prerequisites:
- KDB+ (https://kx.com/connect-with-us/download/)
- C compiler - compatible with your KDB version

Setup:

Compile C sha2 and sha2btc libraries (examples) 
  - Windows dll compilation using VS: cl /LD  /DKXVER=3 sha2.c sha2.def q.lib  
  - Linux so compilation using gcc: gcc -m32 -D KXVER=3 -Wall -fno-strict-aliasing -Wno-parentheses -g -O2 -shared -fPIC -o sha2btc.so sha2btc.c
  - Mac so compilation using gcc: gcc -bundle -undefined dynamic_lookup sha2btc.c -o sha2btc.so

Choose a trusted server for your-server-ip in BTC-miner-opt4.q. Currently coded as the author's server ip. I will add a list as more become available.

Load a q instance with some slaves in the same folder as this repo e.g. q -s 8

Start the q miner

\l BTC-miner-opt4.q

# Servers

In addition to the same setup as the clients, servers require:

 - Bitcoin full node (https://bitcoin.org/en/full-node)

Setup:

Edit rpc-username, rpc-password (and your-public-key-hash or leave as the author address) in BTC-miner-updates4.q

Start bitcoin node and wait for sync.

Load a q instance with some slaves e.g. q -s 4

Start the q server interface

\l BTC-miner-updates4.q

# Credits
Jeremy Lucid from Kx:
https://github.com/jlucid/qbitcoind

# Roadmap

Include all sensible crypto currencies. My order preference:

Security:

1) Bitcoin
2) Litecoin

Scalability:

3) Nano
4) Stellar

Privacy:

5) ZCash
6) Monero

# Karma jar

BTC - 112eMCQJUkUz7kvxDSFCGf1nnFJZ61CE4W

LTC - LR3BfiS77dZcp3KrEkfbXJS7U2vBoMFS7A

ZEC - t1bQpcWAuSg3CkBs29kegBPXvSRSaHqhy2b

XLM - GAHK7EEG2WWHVKDNT4CEQFZGKF2LGDSW2IVM4S5DP42RBW3K6BTODB4A Memo: 1015040538

Nano - nano_1ca5fxd7uk3t61ghjnfd59icxg4ohmbusjthb7supxh3ufef1sykmq77awzh

XRP - rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh Tag: 103535357

EOS - binancecleos Memo: 103117718

# Recommended links

Getting started - [Coinbase](https://www.coinbase.com/join/bradle_6r)

Portfolio balance - [Binance](https://www.binance.com/en/register?ref=LTUMGDDC)

Futures trading - [Deribit](https://www.deribit.com/reg-8106.6912)

Cold wallet - [Atomic](https://atomicWallet.io?kid=12GR52)
