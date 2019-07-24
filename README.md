Solo BTC miner for KDB+


Basic functionality to mine bitcoin blocks. Presently not competitive in speed with other miners. Scaling might be overcome with splayed nonce-hash tables, GPU integration and parallel processing between say a KDB pool of slaves.

Pre-requisits:

Bitcoin full node

KDB+ (https://kx.com/connect-with-us/download/)

C compiler - compatible with your KDB version

(q.lib for 64 bit if your KDB version is 64 bit)

Setup:

Compile C sha2 libraries e.g. for Windows dll compilation using VS - cl /LD  /DKXVER=3 sha2.c sha2.def q.lib  

Edit rpc-username, rpc-password and your-public-key in BTC-miner.q

Run random nonce algo:

Load a q instance with some slaves e.g. q -s 4

\l BTC-miner.q

Contributions and donations welcome.

BTC address: 3QDooeMV1iBuFVxWN5tL7ZqSgBQ4aJUmaq

