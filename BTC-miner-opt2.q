\l cryptoq_binary.q
\l cryptoq.q
\l bitcoind.q

sha256:`sha2 2:(`sha256;2);
sha2560:`sha2btc 2:(`sha2560;1);
sha2561:`sha2btc 2:(`sha2561;3);

h:hopen`:YOU.RE.IP.ADD:5000;
computeData: h"loadUpdates[];computeData";

maxInt:4294967294;
hex: "0123456789abcdef";
htb:"0123456789abcdef"!-4#'0b vs/: hex?hex;
bin_to_int:{0b sv x};
hex_to_int:{0x0 sv x};
hex2bin:{raze htb x};
hex2int:{hex_to_int .cryptoq_binary.bin_to_hex hex2bin x};
doubleSha256:{raze string .cryptoq.hexsha256[raze string[.cryptoq.hexsha256[x]]]};
doubleSha256Byte:{ sha256[sha256[x;count x];32]};
texttohexstr:{raze string "x"$x};
SwapOrder:{raze reverse 2 cut x};
littleEndian:{y#raze string reverse 0x0 vs x};  // int to hexstring

blockcount:{[] .bitcoind.getblockcount[][`result]};

pheaderHex : string last computeData`partialHeader; 
pbyteheaderHex: .cryptoq_binary.hexstring_to_hex raze string pheaderHex;
0N! .z.p;
H0:  sha2560 64#pbyteheaderHex;
target32: .cryptoq_binary.hexstring_to_hex -8#16#string last computeData`target;
leadingzeros:   first where (string last computeData`target) <> "0";
endMerkle: -12#.cryptoq_binary.hexstring_to_hex (string last computeData`partialHeader);
submit:{[headerHex]headstr:raze string headerHex; neg[h] (`.bitcoind.submitheader;headstr);blk: headstr ,string last computeData`trans; h (`.bitcoind.submitblock;blk);0N! "SUCCESS: ", headstr;};
hashcheck:{[finalHash;headerHex]
    if [finalHash[til 7] ~ 0x00000000000000;
        targ: .cryptoq_binary.hexstring_to_hex (string last computeData`target);
        if [finalHash[7] <= targ[7];
            finalHashstr: raze string finalHash;
            lz:first where finalHashstr <> "0";
            $[leadingzeros < lz; 
                [ submit[headerHex]; ];
                [ simpletarget: hex_to_int targ[8 9 10 11];
                    simplehash: hex_to_int finalHash[8 9 10 11];
                    if[ simplehash < simpletarget;submit[headerHex]; ];
                    if [simplehash = simpletarget;
                        simpletarget: hex_to_int targ[12 13 14 15];
                        simplehash: hex_to_int finalHash[12 13 14 15];
                        if[ simplehash < simpletarget;submit[headerHex];];
                        if [simplehash = simpletarget;
                            simpletarget: hex_to_int targ[16 17 18 19];
                            simplehash: hex_to_int finalHash[16 17 18 19];
                            if[ simplehash < simpletarget;submit[headerHex];];
                            if [simplehash = simpletarget;
                                simpletarget: hex_to_int targ[20 21 22 23];
                                simplehash: hex_to_int finalHash[20 21 22 23];
                                if[ simplehash < simpletarget;submit[headerHex];];
                                ];
                            ];
                        ];
                    ]       
                ];            
            ];
        ];
    };
computehash:{[Nonce]    
    headerHex: endMerkle , 4#{reverse 0x0 vs x} Nonce;
    hashcheck[reverse sha2561[ headerHex; H0; target32 ];headerHex];        
    };    

computehash peach til 100000000;    // takes about 10 seconds with 8 slaves. 4.2 billion = 420 iterations -> 4,200 seconds = 1 hour
0N! .z.p;
hclose h;
