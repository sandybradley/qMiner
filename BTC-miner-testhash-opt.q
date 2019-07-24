\l cryptoq_binary.q
\l cryptoq.q

sha256:`sha2 2:(`sha256;2);
sha2560:`sha2btc 2:(`sha2560;1);
sha2561:`sha2btc 2:(`sha2561;2);
sha2562:`sha2btc 2:(`sha2562;2);

doubleSha256Byte:{ sha256[sha256[x;count x];32]};

SwapOrder:{raze reverse 2 cut x};
switcher:{raze string 0x0 vs x};
littleEndian:{8#SwapOrder[switcher[`long$x]]};
        
Version:littleEndian[2]; 
hashPrevBlock:SwapOrder["000000000000000117c80378b8da0e33559b5997f2ad55e2f7d18ec1975b9717"]; 
Time:raze string reverse[0x53058b35];
Bits:raze string reverse[0x19015f53];
target: "0000000000000000e057a478024addfecdc93628978aa52d91fabd4292982a50"; 
Merkleroot:SwapOrder["871714dcbae6c8193a2bb9b2a69fe1c0440399f38d94b3a0f1b447275a29978a"]; 

partialHeader :  Version , hashPrevBlock , Merkleroot , Time , Bits ;
   
Nonce: 856192328;

headerHex : partialHeader , raze string littleEndian Nonce; 
byteheaderHex:  .cryptoq_binary.hexstring_to_hex raze string headerHex;
finalHash : 0N!  reverse doubleSha256Byte[byteheaderHex]; 
H0:   sha2560 64#byteheaderHex;
H1:  sha2561[-16#byteheaderHex;H0];
target32: .cryptoq_binary.hexstring_to_hex -8#16#target;
finalHash2: 0N! reverse sha2562[H1;target32];

