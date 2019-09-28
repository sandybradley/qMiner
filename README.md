# Design principle 

Optimised CPU miner for efficient deployment on every device.

- KDB+ is lightweight, cross-platform, independent and the most powerful CPU parallel processing database for mass real-time co-ordinaton.

Why CPU ? - CPU miners are more energy efficient and mass accessible. 

Why co-ordinate ? - Instead of an exponentially increasing has power competition, we can have an energy efficient co-ordinated effort. i.e. less waste.

What is the incentive ? - Positive incentive feedback structures are important for sustainability and popularity. Here is my proposed structure:

1 % - Who-ever finds the solution for the current block first.

39 % - Split proportionally to the resources dedicated to mining the current block.

30 % - Universal income, claimable daily by low income families accross the planet.

30 % - Earth care trust, claimable by environmental revival projects. 

# How it works

1 low latency server. Multiple CPU clients.

Prerequisites:

Server:

Bitcoin full node


Server and clients:

KDB+ (https://kx.com/connect-with-us/download/)

C compiler - compatible with your KDB version

(q.lib for 64 bit if your KDB version is 64 bit)


Setup:

Compile C sha2 libraries e.g. for Windows dll compilation using VS - cl /LD  /DKXVER=3 sha2.c sha2.def q.lib  

Edit rpc-username, rpc-password and your-public-key in BTC-miner-updates3.q

Server:

Start bitcoin node and wait for sync.

Load a q instance with some slaves e.g. q -s 4

Start the q server interface

\l BTC-miner-updates3.q

Clients:

Load a q instance with some slaves e.g. q -s 8

Start the q miner

\l BTC-miner-opt3.q


Contributions and donations welcome.

BTC address: 3QDooeMV1iBuFVxWN5tL7ZqSgBQ4aJUmaq

