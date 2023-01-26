/* 
 * NPLIB SHA3 module
 *
 * Version 1.00
 * Copyright (C) 2012-2023 Nicolas Provost dev AT npsoft DOT fr
 * All rights reserved.
 */

#ifndef __BSDSUM_SHA3_H
#define __BSDSUM_SHA3_H

#include <stdint.h>
#include <stdbool.h>

/*************************************************************************
The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
Michael Peeters and Gilles Van Assche. For more information, feedback or
questions, please refer to our website: http://keccak.noekeon.org/

Implementation by the designers,
hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#define KeccakPermutationSize 1600
#define KeccakPermutationSizeInBytes (KeccakPermutationSize/8)
#define KeccakMaximumRate 1536
#define KeccakMaximumRateInBytes (KeccakMaximumRate/8)

#if defined(__GNUC__)
#define ALIGN __attribute__ ((aligned(32)))
#elif defined(_MSC_VER)
#define ALIGN __declspec(align(32))
#else
#define ALIGN
#endif

ALIGN typedef struct spongeStateStruct
{
    ALIGN unsigned char state[KeccakPermutationSizeInBytes];
    ALIGN unsigned char dataQueue[KeccakMaximumRateInBytes];
    unsigned int rate;
    unsigned int capacity;
    unsigned int bitsInQueue;
    unsigned int fixedOutputLength;
    int squeezing;
    unsigned int bitsAvailableForSqueezing;
} spongeState;
/*************************************************************************/


typedef unsigned char sha3_256_hash[32];
typedef unsigned char sha3_512_hash[64];

typedef union
{
    sha3_256_hash dg256;
    sha3_512_hash dg512;
} bsdsum_sha3_hash_t;

#define SHA3_256_BLOCK_SIZE (1088/8)
#define SHA3_512_BLOCK_SIZE (576/8)
#define SHA3_BUF_LEN 144

typedef struct bsdsum_sha3_ctx_t
{
    spongeState state;
    size_t len;                   /**< size of output (32 or 64) */
    bool hmac_started;
    bool initialized;          /**< TRUE if initialized */
    union
    {
        unsigned char s256[SHA3_256_BLOCK_SIZE];
        unsigned char s512[SHA3_512_BLOCK_SIZE];
    } ipad;     /**< HMAC inner padding */
    union
    {
        unsigned char s256[SHA3_256_BLOCK_SIZE + 32];
        unsigned char s512[SHA3_512_BLOCK_SIZE + 64];
    } opad;     /**< HMAC outer padding */
} bsdsum_sha3_ctx_t;

void bsdsum_sha3_256_begin (bsdsum_sha3_ctx_t *cx);

void bsdsum_sha3_512_begin (bsdsum_sha3_ctx_t *cx);

bool bsdsum_sha3_update (bsdsum_sha3_ctx_t *cx,
     	             const unsigned char *input, size_t inputLen);

void bsdsum_sha3_final (unsigned char *dg, bsdsum_sha3_ctx_t *cx);


#endif

