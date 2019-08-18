/* sha2btc.c - SHA 256 bitcoin optimised using C for KDB+  */
/* Adapted by Alexander Bradley from Jeffrey Walton's sha and Jeremy Lucid's kdb interface and  */
/* // http://www.nicolascourtois.com/bitcoin/Optimising%20the%20SHA256%20Hashing%20Algorithm%20for%20Faster%20and%20More%20Efficient%20Bitcoin%20Mining_Rahul_Naik.pdf */

/* in same folder include k.h, q.lib and sha2.def (EXPORTS sha256)  */
/* for Windows dll compilation using VS  */
/* cl /LD  /DKXVER=3 sha2btc.c sha2btc.def q.lib  */
/* to load function in kdb instance */
/* sha2560:`sha2btc 2:(`sha2560;1) */
/* sha2561:`sha2btc 2:(`sha2561;2) */
/* sha2562:`sha2btc 2:(`sha2562;1) */
/* function takes an input list (bytes, chars, numbers ) */
/* sha2560[0x32ed32] */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "k.h"

static const uint32_t K256[] =
    {
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2};

#define ROTATE(x, y) (((x) >> (y)) | ((x) << (32 - (y))))
#define Sigma0(x) (ROTATE((x), 2) ^ ROTATE((x), 13) ^ ROTATE((x), 22))
#define Sigma1(x) (ROTATE((x), 6) ^ ROTATE((x), 11) ^ ROTATE((x), 25))
#define sigma0(x) (ROTATE((x), 7) ^ ROTATE((x), 18) ^ ((x) >> 3))
#define sigma1(x) (ROTATE((x), 17) ^ ROTATE((x), 19) ^ ((x) >> 10))

#define Ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* Avoid undefined behavior                    */
/* https://stackoverflow.com/q/29538935/608639 */
uint32_t B2U32(uint8_t val, uint8_t sh)
{
    return ((uint32_t)val) << sh;
}

/* Process multiple blocks. The caller is responsible for setting the initial */
/*  state, and the caller is responsible for padding the final block.        */
void sha256_process(uint32_t state[8], const uint8_t data[], uint32_t length)
{
    uint32_t a, b, c, d, e, f, g, h, s0, s1, T1, T2;
    uint32_t X[16], i;

    size_t blocks = length / 64;
    while (blocks--)
    {
        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];

        for (i = 0; i < 16; i++)
        {
            X[i] = B2U32(data[0], 24) | B2U32(data[1], 16) | B2U32(data[2], 8) | B2U32(data[3], 0);
            data += 4;

            T1 = h;
            T1 += Sigma1(e);
            T1 += Ch(e, f, g);
            T1 += K256[i];
            T1 += X[i];

            T2 = Sigma0(a);
            T2 += Maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        for (; i < 64; i++)
        {
            s0 = X[(i + 1) & 0x0f];
            s0 = sigma0(s0);
            s1 = X[(i + 14) & 0x0f];
            s1 = sigma1(s1);

            T1 = X[i & 0xf] += s0 + s1 + X[(i + 9) & 0xf];
            T1 += h + Sigma1(e) + Ch(e, f, g) + K256[i];
            T2 = Sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }
}
void sha2562_process(uint32_t state[8], const uint8_t data[], uint32_t length, uint32_t target)
{
    uint32_t a, b, c, d, e, f, g, h, s0, s1, T1, T2;
    uint32_t X[16], i;

    size_t blocks = length / 64;
    while (blocks--)
    {
        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];

        for (i = 0; i < 16; i++)
        {
            X[i] = B2U32(data[0], 24) | B2U32(data[1], 16) | B2U32(data[2], 8) | B2U32(data[3], 0);
            data += 4;

            T1 = h;
            T1 += Sigma1(e);
            T1 += Ch(e, f, g);
            T1 += K256[i];
            T1 += X[i];

            T2 = Sigma0(a);
            T2 += Maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        for (; i < 64; i++)
        {
            
            s0 = X[(i + 1) & 0x0f];
            s0 = sigma0(s0);
            s1 = X[(i + 14) & 0x0f];
            s1 = sigma1(s1);

            T1 = X[i & 0xf] += s0 + s1 + X[(i + 9) & 0xf];
            T1 += h + Sigma1(e) + Ch(e, f, g) + K256[i];
            T2 = Sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;

            // Opt 2 - early rejection check
            if (i == 60){
               uint32_t tmpy = e + 0x5BE0CD19;
               if (tmpy != 0){
                   state[0] = 0x5BE0CD19;
                   return;
               }               
            }
            if (i == 61){
                //uint32_t tmpy = little_endian(e+0x1F83D9AB);
                uint32_t tmpy = e+0x1F83D9AB;
                uint32_t swapped = ((tmpy>>24)&0xff) | ((tmpy>>16)&0xff) | ((tmpy>>8)&0xff) | (tmpy&0xff); 
                printf("%0x\n",swapped);
                if (swapped > target){
                    state[0] = 0x5BE0CD19;
                    return;
                }                
            }
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }
}

// Opt 1 - Calculate first part (static) of sha header
// 4 byte version, 32 bytes hashPrevBlock, 28 bytes hashMerkleroot

K sha2560(K inputString)
{
    // set variables
    K outputHash;
    uint32_t i, j;
    uint8_t message[64];
    outputHash = ktn(KI, 8);
    for (i = 0; i < 64; i++)
    {
        message[i] = kG(inputString)[i];
    }
    /* initial state */
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    sha256_process(state, message, 64);
    
    for (i = 0; i < 8; i++)
    {
        kI(outputHash)[i] = state[i];        
    }
    return outputHash;
}
// 
K sha2561(K inputString, K H0, K target)
{
    // set variables
    K outputHash;
    uint32_t targ = target->i;
    uint32_t i, j;
    uint32_t bitlength = 8 * 80;
    int w = 319;
    int numbytes = (int)((w + 1) / 8);
    int messagelen = 64;
    uint8_t message[64];
    outputHash = ktn(KG, 32);
    for (i = 0; i < 16; i++)
    {
        message[i] = kG(inputString)[i];
    }
    message[i] = 0x80;
    for (j = 1; j < numbytes; j++)
    {
        message[i + j] = 0x00;
    }
    message[i + j] = 0x00;
    message[i + j + 1] = 0x00;
    message[i + j + 2] = 0x00;
    message[i + j + 3] = 0x00;
    message[i + j + 4] = (bitlength >> 24) & 0xFF;
    message[i + j + 5] = (bitlength >> 16) & 0xFF;
    message[i + j + 6] = (bitlength >> 8) & 0xFF;
    message[i + j + 7] = bitlength & 0xFF;

    /* H0 state */
    uint32_t state[8];
    for (i=0;i<8;i++){
        state[i] = kI(H0)[i] ;
    }   
    
    sha256_process(state, message, messagelen);
    memset(message, 0x00, 64);
    j = 0;
    for (i = 0; i < 8; i++)
    {
        message[j + 0] = (uint8_t)(state[i] >> 24);
        message[j + 1] = (uint8_t)(state[i] >> 16);
        message[j + 2] = (uint8_t)(state[i] >> 8);
        message[j + 3] = (uint8_t)(state[i] >> 0);
        j = j + 4;
    }
    
    bitlength = 8 * 32;
    w = 191;
    numbytes = (int)((w + 1) / 8);
    messagelen = 64;
    i=32;
    message[i] = 0x80;
    for (j = 1; j < numbytes; j++)
    {
        message[i + j] = 0x00;
    }
    message[i + j] = 0x00;
    message[i + j + 1] = 0x00;
    message[i + j + 2] = 0x00;
    message[i + j + 3] = 0x00;
    message[i + j + 4] = (bitlength >> 24) & 0xFF;
    message[i + j + 5] = (bitlength >> 16) & 0xFF;
    message[i + j + 6] = (bitlength >> 8) & 0xFF;
    message[i + j + 7] = bitlength & 0xFF;

    /* initial state */
    uint32_t state1[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    sha2562_process(state1, message, messagelen, targ);

    // Opt 2 - early rejection check, for now just assign large number to be rejected
    if(state1[0] == 0x5BE0CD19){
        for (i = 0; i < 32; i++){
            kG(outputHash)[i]=0x5B;
        }
        return outputHash;
    }
    j = 0;
    for (i = 0; i < 8; i++)
    {
        kG(outputHash)[j + 0] = (uint8_t)(state1[i] >> 24);
        kG(outputHash)[j + 1] = (uint8_t)(state1[i] >> 16);
        kG(outputHash)[j + 2] = (uint8_t)(state1[i] >> 8);
        kG(outputHash)[j + 3] = (uint8_t)(state1[i] >> 0);
        j = j + 4;
    }
    return outputHash;
}

K shadebug(K inputString)
{
    // set variables
    K outputHash;
    uint32_t i, j;
    uint8_t *message = (uint8_t *)malloc(64);
    uint32_t bitlength = 8 * 80;
    int w = 319;
    int numbytes = (int)((w + 1) / 8);
    int messagelen = 64;    
    memset(message, 0x00, 64);
    outputHash = ktn(KG, 32);
    for (i = 0; i < 64; i++)
    {
        message[i] = kG(inputString)[i];
    }
    /* initial state */
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    sha256_process(state, message, 64);    
    memset(message, 0x00, 64);
    for (i = 0; i < 16; i++)
    {
        message[i] = kG(inputString)[(i+64)];
    }
    message[i] = 0x80;
    for (j = 1; j < numbytes; j++)
    {
        message[i + j] = 0x00;
    }
    message[i + j] = 0x00;
    message[i + j + 1] = 0x00;
    message[i + j + 2] = 0x00;
    message[i + j + 3] = 0x00;
    message[i + j + 4] = (bitlength >> 24) & 0xFF;
    message[i + j + 5] = (bitlength >> 16) & 0xFF;
    message[i + j + 6] = (bitlength >> 8) & 0xFF;
    message[i + j + 7] = bitlength & 0xFF;
    
    sha256_process(state, message, messagelen);
    memset(message, 0x00, 64);
    j = 0;
    for (i = 0; i < 8; i++)
    {
        message[j + 0] = (uint8_t)(state[i] >> 24);
        message[j + 1] = (uint8_t)(state[i] >> 16);
        message[j + 2] = (uint8_t)(state[i] >> 8);
        message[j + 3] = (uint8_t)(state[i] >> 0);
        //printf("%0x%0x%0x%0x",message[j + 0],message[j + 1],message[j + 2],message[j + 3]);
        j = j + 4;
    }
    //printf("\n");
    
    bitlength = 8 * 32;
    w = 191;
    numbytes = (int)((w + 1) / 8);
    messagelen = 64;
    i=32;
    message[i] = 0x80;
    for (j = 1; j < numbytes; j++)
    {
        message[i + j] = 0x00;
    }
    message[i + j] = 0x00;
    message[i + j + 1] = 0x00;
    message[i + j + 2] = 0x00;
    message[i + j + 3] = 0x00;
    message[i + j + 4] = (bitlength >> 24) & 0xFF;
    message[i + j + 5] = (bitlength >> 16) & 0xFF;
    message[i + j + 6] = (bitlength >> 8) & 0xFF;
    message[i + j + 7] = bitlength & 0xFF;

    /* initial state */
     uint32_t state1[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    sha256_process(state1, message, messagelen);

    j = 0;
    for (i = 0; i < 8; i++)
    {
        kG(outputHash)[j + 0] = (uint8_t)(state1[i] >> 24);
        kG(outputHash)[j + 1] = (uint8_t)(state1[i] >> 16);
        kG(outputHash)[j + 2] = (uint8_t)(state1[i] >> 8);
        kG(outputHash)[j + 3] = (uint8_t)(state1[i] >> 0);
        j = j + 4;
    }
    free(message);
    return outputHash;
}
