\p 5000

\l cryptoq_binary.q
\l cryptoq.q
\l bitcoind.q

sha256:`sha2 2:(`sha256;2);

username:"rpc-username";
password:"rpc-password";

computeData: ([]blockHeight:"f"$(); partialHeader:`$(); trans:`$(); target:`$()  );

initHeight:0f;
flag:1b;
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
buildmerkleroot:{[leafs] 
    leafcount:  count leafs;
    root:  $[1 = leafcount;
        first leafs;
        [
            if [0 < leafcount mod 2; leafs: leafs,enlist last leafs; leafcount: 1+leafcount;]; // if odd number, duplicate last record
            oddindicies: 1+2*til "i"$(leafcount%2);
            evenindicies: 2*til "i"$(leafcount%2);
            hashpairs: leafs[evenindicies] ,' leafs[oddindicies];
            hashcount:  count hashpairs;
            branches:{  doubleSha256Byte x } peach hashpairs;  
            buildmerkleroot[branches]
            ]
        ];
    root    
    };


template_request: `mode`capabilities`rules!("template";(enlist "proposal");enlist "segwit");
coinbaseversion:"01000000";
coinbasein:"01";
coinbaseprevtx:"0000000000000000000000000000000000000000000000000000000000000000";
coinbaseprevout:"ffffffff";
coinbaseseq:"00000000";
coinbaseout:"01";
cbpubkey: "866b6c77fd236f9185bb11b4e176328d7f912a4b";
scriptPubKey: "76","A9","14" , cbpubkey, "88", "AC";
coinbasesl: "19";
coinbaselocktime:"00000000";

.bitcoind.initPass[username;password];

blockcount:{[] .bitcoind.getblockcount[][`result]};
loadUpdates:{[]        
    template: .bitcoind.getblocktemplate[template_request][`result];
    Version:littleEndian[template[`version];8]; 
    hashPrevBlock:SwapOrder[template[`previousblockhash]]; 
    Time:littleEndian[template[`curtime];8];
    Bits:SwapOrder[template[`bits]];
    target: template[`target]; 
    height: 0N! template[`height]; 
    if[initHeight < height; initHeight::height; ];
    cheight: height;
    coinbasevalue:template[`coinbasevalue];
    coinbasesats: littleEndian[coinbasevalue;16];
    coinbasescript:"03" , (littleEndian[height;6]), texttohexstr["Mined by Sandy Bay"];
    coinbasescriptlen:littleEndian["i"$(count coinbasescript)%2;2];
    coinbasesommy:coinbasescript;
    coinbasescriptlen:littleEndian["i"$(count coinbasesommy)%2;2];
    coinbasetrans: coinbaseversion, coinbasein, coinbaseprevtx, coinbaseprevout,coinbasescriptlen,coinbasesommy,coinbaseseq,coinbaseout,coinbasesats,coinbasesl,scriptPubKey,coinbaselocktime;
    coinbasetransbytes: .cryptoq_binary.hexstring_to_hex raze string coinbasetrans;
    coinbasetranshash:raze string reverse doubleSha256Byte[coinbasetransbytes];
    transactions: template[`transactions]; 
    hashlist:transactions[;`hash];
    datalist:transactions[;`data];
    hashlist: (enlist coinbasetranshash), hashlist;
    bytehashlist:.cryptoq_binary.hexstring_to_hex peach hashlist;
    bytehashlistBigEndian:reverse peach bytehashlist;
    Merkleroot: buildmerkleroot[bytehashlistBigEndian]; 

    partialHeader : Version , hashPrevBlock , Merkleroot , Time , Bits ;
    trans:(enlist coinbasetrans),datalist;
    transcounter:littleEndian[count trans;8];
    blk: transcounter , raze trans; 

    `computeData insert (blockHeight:height; partialHeader:`$raze string partialHeader; trans:`$raze string blk; target:`$raze string target  );
    };

