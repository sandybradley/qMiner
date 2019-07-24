// Test hash calculation
// Data from Block #286819
// final hash: 0x0000000000000000e067a478024addfecdc93628978aa52d91fabd4292982a50
\l cryptoq_binary.q
\l cryptoq.q

sha256:`sha2 2:(`sha256;2);
doubleSha256Byte:{ sha256[sha256[x;count x];32]};
SwapOrder:{raze reverse 2 cut x};
littleEndian:{y#raze string reverse 0x0 vs x};  // int to hexstring
        
Version:littleEndian[2;8]; 
hashPrevBlock:SwapOrder["000000000000000117c80378b8da0e33559b5997f2ad55e2f7d18ec1975b9717"]; 
Time:raze string reverse[0x53058b35];
Bits:raze string reverse[0x19015f53];
target: "0000000000000000e057a478024addfecdc93628978aa52d91fabd4292982a50"; 
Merkleroot:SwapOrder["871714dcbae6c8193a2bb9b2a69fe1c0440399f38d94b3a0f1b447275a29978a"]; 

partialHeader :  Version , hashPrevBlock , Merkleroot , Time , Bits ;
   
Nonce: 856192328;

headerHex : 0N! partialHeader , raze string littleEndian[Nonce;8]; 
byteheaderHex:  .cryptoq_binary.hexstring_to_hex raze string headerHex;
finalHash : raze string reverse doubleSha256Byte[byteheaderHex]; 
0N! finalHash;
leadingzeros:   first where  target <> "0";
lzh:  first where finalHash <> "0";
if[lzh > leadingzeros;
    0N! "YES!";        
    ];
if[lzh = leadingzeros;
    simpletarget: hex_to_int .cryptoq_binary.hexstring_to_hex (string last target)[leadingzeros + til 8];
    simplehash: hex_to_int .cryptoq_binary.hexstring_to_hex finalHash[leadingzeros + til 8];
    if[ simplehash < simpletarget;
        0N! "YES!";        
        ];
    ];
