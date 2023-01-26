/*
 * Copyright (c) 2022-2023
 *      Nicolas Provost <dev AT npsoft DOT fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * The original Keccak reference code below is public-domain.
 */

#include <string.h>
#include "bsdsum_sha3.h"

/*===========================================================================
  = ORIGINAL KECCAK REFERENCE CODE                                          =
  ===========================================================================*/

/*
The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
Michael Peeters and Gilles Van Assche. For more information, feedback or
questions, please refer to our website: http://keccak.noekeon.org/

Implementation by the designers,
hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/
typedef unsigned char UINT8;
typedef unsigned int UINT32;

#define nrRounds 24
UINT32 KeccakRoundConstants[nrRounds][2];
#define nrLanes 25
unsigned int KeccakRhoOffsets[nrLanes];

static void KeccakPermutationOnWords (UINT32 * state);
static void theta (UINT32 * A);
static void rho (UINT32 * A);
static void pi (UINT32 * A);
static void chi (UINT32 * A);
static void iota (UINT32 * A, unsigned int indexRound);

static void
toBitInterleaving (UINT32 low, UINT32 high, UINT32 * even, UINT32 * odd)
{
    unsigned int i;

    *even = 0;
    *odd = 0;
    for (i = 0; i < 64; i++)
      {
          unsigned int inBit;
          if (i < 32)
              inBit = (low >> i) & 1;
          else
              inBit = (high >> (i - 32)) & 1;
          if ((i % 2) == 0)
              *even |= inBit << (i / 2);
          else
              *odd |= inBit << ((i - 1) / 2);
      }
}

static void
fromBitInterleaving (UINT32 even, UINT32 odd, UINT32 * low, UINT32 * high)
{
    unsigned int i;

    *low = 0;
    *high = 0;
    for (i = 0; i < 64; i++)
      {
          unsigned int inBit;
          if ((i % 2) == 0)
              inBit = (even >> (i / 2)) & 1;
          else
              inBit = (odd >> ((i - 1) / 2)) & 1;
          if (i < 32)
              *low |= inBit << i;
          else
              *high |= inBit << (i - 32);
      }
}

static void
fromBytesToWords (UINT32 * stateAsWords, const unsigned char *state)
{
    unsigned int i, j;
    UINT32 low, high;
    UINT32 even, odd;

    for (i = 0; i < (KeccakPermutationSize / 64); i++)
      {
          low = 0;
          high = 0;
          for (j = 0; j < (32 / 8); j++)
              low |= (UINT32) (state[i * (64 / 8) + j]) << (8 * j);
          for (j = (32 / 8); j < (64 / 8); j++)
              high |= (UINT32) (state[i * (64 / 8) + j]) << (8 * j - 32);
          toBitInterleaving (low, high, &even, &odd);
          stateAsWords[2 * i + 0] = even;
          stateAsWords[2 * i + 1] = odd;
      }
}

static void
fromWordsToBytes (unsigned char *state, const UINT32 * stateAsWords)
{
    unsigned int i, j;
    UINT32 low, high;

    for (i = 0; i < (KeccakPermutationSize / 64); i++)
      {
          fromBitInterleaving (stateAsWords[2 * i + 0],
                               stateAsWords[2 * i + 1], &low, &high);
          for (j = 0; j < (32 / 8); j++)
              state[i * (64 / 8) + j] = (low >> (8 * j)) & 0xFF;
          for (j = 32 / 8; j < (64 / 8); j++)
              state[i * (64 / 8) + j] = (high >> (8 * j - 32)) & 0xFF;
      }
}

static void
KeccakPermutation (unsigned char *state)
{
    UINT32 stateAsWords[KeccakPermutationSize / 32];

    fromBytesToWords (stateAsWords, state);
    KeccakPermutationOnWords (stateAsWords);
    fromWordsToBytes (state, stateAsWords);
}

static void
KeccakPermutationAfterXor (unsigned char *state,
                           const unsigned char *data,
                           unsigned int dataLengthInBytes)
{
    unsigned int i;

    for (i = 0; i < dataLengthInBytes; i++)
        state[i] ^= data[i];
    KeccakPermutation (state);
}

static void
KeccakPermutationOnWords (UINT32 * state)
{
    unsigned int i;

    for (i = 0; i < nrRounds; i++)
      {
          theta (state);
          rho (state);
          pi (state);
          chi (state);
          iota (state, i);
      }
}

#define index(x, y,z) ((((x)%5)+5*((y)%5))*2 + z)
#define ROL32(a, offset) ((offset != 0) ? ((((UINT32)a) << offset) ^ (((UINT32)a) >> (32-offset))) : a)

static void
ROL64 (UINT32 inEven, UINT32 inOdd, UINT32 * outEven,
       UINT32 * outOdd, unsigned int offset)
{
    if ((offset % 2) == 0)
      {
          *outEven = ROL32 (inEven, offset / 2);
          *outOdd = ROL32 (inOdd, offset / 2);
      }
    else
      {
          *outEven = ROL32 (inOdd, (offset + 1) / 2);
          *outOdd = ROL32 (inEven, (offset - 1) / 2);
      }
}

static void
theta (UINT32 * A)
{
    unsigned int x, y, z;
    UINT32 C[5][2], D[5][2];

    for (x = 0; x < 5; x++)
      {
          for (z = 0; z < 2; z++)
            {
                C[x][z] = 0;
                for (y = 0; y < 5; y++)
                    C[x][z] ^= A[index (x, y, z)];
            }
      }
    for (x = 0; x < 5; x++)
      {
          ROL64 (C[(x + 1) % 5][0], C[(x + 1) % 5][1], &(D[x][0]), &(D[x][1]),
                 1);
          for (z = 0; z < 2; z++)
              D[x][z] ^= C[(x + 4) % 5][z];
      }
    for (x = 0; x < 5; x++)
        for (y = 0; y < 5; y++)
            for (z = 0; z < 2; z++)
                A[index (x, y, z)] ^= D[x][z];
}

static void
rho (UINT32 * A)
{
    unsigned int x, y;

    for (x = 0; x < 5; x++)
        for (y = 0; y < 5; y++)
            ROL64 (A[index (x, y, 0)], A[index (x, y, 1)],
                   &(A[index (x, y, 0)]), &(A[index (x, y, 1)]),
                   KeccakRhoOffsets[5 * y + x]);
}

static void
pi (UINT32 * A)
{
    unsigned int x, y, z;
    UINT32 tempA[50];

    for (x = 0; x < 5; x++)
        for (y = 0; y < 5; y++)
            for (z = 0; z < 2; z++)
                tempA[index (x, y, z)] = A[index (x, y, z)];
    for (x = 0; x < 5; x++)
        for (y = 0; y < 5; y++)
            for (z = 0; z < 2; z++)
                A[index (0 * x + 1 * y, 2 * x + 3 * y, z)] =
                    tempA[index (x, y, z)];
}

static void
chi (UINT32 * A)
{
    unsigned int x, y, z;
    UINT32 C[5][2];

    for (y = 0; y < 5; y++)
      {
          for (x = 0; x < 5; x++)
              for (z = 0; z < 2; z++)
                  C[x][z] =
                      A[index (x, y, z)] ^ ((~A[index (x + 1, y, z)]) &
                                            A[index (x + 2, y, z)]);
          for (x = 0; x < 5; x++)
              for (z = 0; z < 2; z++)
                  A[index (x, y, z)] = C[x][z];
      }
}

static void
iota (UINT32 * A, unsigned int indexRound)
{
    A[index (0, 0, 0)] ^= KeccakRoundConstants[indexRound][0];
    A[index (0, 0, 1)] ^= KeccakRoundConstants[indexRound][1];
}

static int
LFSR86540 (UINT8 * LFSR)
{
    int result = ((*LFSR) & 0x01) != 0;
    if (((*LFSR) & 0x80) != 0)
        // Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1
        (*LFSR) = ((*LFSR) << 1) ^ 0x71;
    else
        (*LFSR) <<= 1;
    return result;
}

static void
KeccakInitializeRoundConstants ()
{
    UINT8 LFSRstate = 0x01;
    unsigned int i, j, bitPosition;
    UINT32 low, high;

    for (i = 0; i < nrRounds; i++)
      {
          low = high = 0;
          for (j = 0; j < 7; j++)
            {
                bitPosition = (1 << j) - 1;     //2^j-1
                if (LFSR86540 (&LFSRstate))
                  {
                      if (bitPosition < 32)
                          low ^= (UINT32) 1 << bitPosition;
                      else
                          high ^= (UINT32) 1 << (bitPosition - 32);
                  }
            }
          toBitInterleaving (low, high, &(KeccakRoundConstants[i][0]),
                             &(KeccakRoundConstants[i][1]));
      }
}

static void
KeccakInitializeRhoOffsets ()
{
    unsigned int x, y, t, newX, newY;

    KeccakRhoOffsets[0] = 0;
    x = 1;
    y = 0;
    for (t = 0; t < 24; t++)
      {
          KeccakRhoOffsets[5 * y + x] = ((t + 1) * (t + 2) / 2) % 64;
          newX = (0 * x + 1 * y) % 5;
          newY = (2 * x + 3 * y) % 5;
          x = newX;
          y = newY;
      }
}

static void
KeccakInitialize ()
{
    KeccakInitializeRoundConstants ();
    KeccakInitializeRhoOffsets ();
}

static void
KeccakInitializeState (unsigned char *state)
{
    memset (state, 0, KeccakPermutationSizeInBytes);
}

static void
KeccakAbsorb (unsigned char *state, const unsigned char *data,
              unsigned int laneCount)
{
    KeccakPermutationAfterXor (state, data, laneCount * 8);
}

static void
KeccakExtract (const unsigned char *state, unsigned char *data,
               unsigned int laneCount)
{
    memcpy (data, state, laneCount * 8);
}

/*
The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
Michael Peeters and Gilles Van Assche. For more information, feedback or
questions, please refer to our website: http://keccak.noekeon.org/

Implementation by the designers,
hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

static int
InitSponge (spongeState * state, unsigned int rate, unsigned int capacity)
{
    if (rate + capacity != 1600)
        return 1;
    if ((rate <= 0) || (rate >= 1600) || ((rate % 64) != 0))
        return 1;
    KeccakInitialize ();
    state->rate = rate;
    state->capacity = capacity;
    state->fixedOutputLength = 0;
    KeccakInitializeState (state->state);
    memset (state->dataQueue, 0, KeccakMaximumRateInBytes);
    state->bitsInQueue = 0;
    state->squeezing = 0;
    state->bitsAvailableForSqueezing = 0;
    return 0;
}

static void
AbsorbQueue (spongeState * state)
{
    // state->bitsInQueue is assumed to be equal to state->rate
    KeccakAbsorb (state->state, state->dataQueue, state->rate / 64);
    state->bitsInQueue = 0;
}

static int
Absorb (spongeState * state, const unsigned char *data,
        unsigned long long databitlen)
{
    unsigned long long i, j, wholeBlocks;
    unsigned int partialBlock, partialByte;
    const unsigned char *curData;

    if ((state->bitsInQueue % 8) != 0)
        return 1;               // Only the last call may contain a partial byte
    if (state->squeezing)
        return 1;               // Too late for additional input

    i = 0;
    while (i < databitlen)
      {
          if ((state->bitsInQueue == 0) && (databitlen >= state->rate)
              && (i <= (databitlen - state->rate)))
            {
                wholeBlocks = (databitlen - i) / state->rate;
                curData = data + i / 8;
                {
                    for (j = 0; j < wholeBlocks;
                         j++, curData += state->rate / 8)
                      {
#ifdef KeccakReference
                          displayBytes (1, "Block to be absorbed", curData,
                                        state->rate / 8);
#endif
                          KeccakAbsorb (state->state, curData,
                                        state->rate / 64);
                      }
                }
                i += wholeBlocks * state->rate;
            }
          else
            {
                partialBlock = (unsigned int) (databitlen - i);
                if (partialBlock + state->bitsInQueue > state->rate)
                    partialBlock = state->rate - state->bitsInQueue;
                partialByte = partialBlock % 8;
                partialBlock -= partialByte;
                memcpy (state->dataQueue + state->bitsInQueue / 8,
                        data + i / 8, partialBlock / 8);
                state->bitsInQueue += partialBlock;
                i += partialBlock;
                if (state->bitsInQueue == state->rate)
                    AbsorbQueue (state);
                if (partialByte > 0)
                  {
                      unsigned char mask = (1 << partialByte) - 1;
                      state->dataQueue[state->bitsInQueue / 8] =
                          data[i / 8] & mask;
                      state->bitsInQueue += partialByte;
                      i += partialByte;
                  }
            }
      }
    return 0;
}

static void
PadAndSwitchToSqueezingPhase (spongeState * state)
{
    // Note: the bits are numbered from 0=LSB to 7=MSB
    if (state->bitsInQueue + 1 == state->rate)
      {
          state->dataQueue[state->bitsInQueue / 8] |=
              1 << (state->bitsInQueue % 8);
          AbsorbQueue (state);
          memset (state->dataQueue, 0, state->rate / 8);
      }
    else
      {
          memset (state->dataQueue + (state->bitsInQueue + 7) / 8, 0,
                  state->rate / 8 - (state->bitsInQueue + 7) / 8);
          state->dataQueue[state->bitsInQueue / 8] |=
              1 << (state->bitsInQueue % 8);
      }
    state->dataQueue[(state->rate - 1) / 8] |= 1 << ((state->rate - 1) % 8);
    AbsorbQueue (state);

    {
        KeccakExtract (state->state, state->dataQueue, state->rate / 64);
        state->bitsAvailableForSqueezing = state->rate;
    }
    state->squeezing = 1;
}

static int
Squeeze (spongeState * state, unsigned char *output,
         unsigned long long outputLength)
{
    unsigned long long i;
    unsigned int partialBlock;

    if (!state->squeezing)
        PadAndSwitchToSqueezingPhase (state);
    if ((outputLength % 8) != 0)
        return 1;               // Only multiple of 8 bits are allowed, truncation can be done at user level

    i = 0;
    while (i < outputLength)
      {
          if (state->bitsAvailableForSqueezing == 0)
            {
                KeccakPermutation (state->state);
                {
                    KeccakExtract (state->state, state->dataQueue,
                                   state->rate / 64);
                    state->bitsAvailableForSqueezing = state->rate;
                }
            }
          partialBlock = state->bitsAvailableForSqueezing;
          if ((unsigned long long) partialBlock > outputLength - i)
              partialBlock = (unsigned int) (outputLength - i);
          memcpy (output + i / 8,
                  state->dataQueue + (state->rate -
                                      state->bitsAvailableForSqueezing) / 8,
                  partialBlock / 8);
          state->bitsAvailableForSqueezing -= partialBlock;
          i += partialBlock;
      }
    return 0;
}

/* NIST INTERFACE */
typedef unsigned char BitSequence;
typedef unsigned long long DataLength;
typedef enum
{ SUCCESS = 0, FAIL = 1, BAD_HASHLEN = 2 } HashReturn;

typedef spongeState hashState;

/*
  * Function to initialize the state of the Keccak[r, c] sponge function.
  * The rate r and capacity c values are determined from @a hashbitlen.
  * @param  state       Pointer to the state of the sponge function to be initialized.
  * @param  hashbitlen  The desired number of output bits, 
  *                     or 0 for Keccak[] with default parameters
  *                     and arbitrarily-long output.
  * @pre    The value of hashbitlen must be one of 0, 224, 256, 384 and 512.
  * @return SUCCESS if successful, BAD_HASHLEN if the value of hashbitlen is incorrect.
  */
static HashReturn
Init (hashState * state, int hashbitlen)
{
    switch (hashbitlen)
      {
      case 0:                  // Default parameters, arbitrary length output
          InitSponge ((spongeState *) state, 1024, 576);
          break;
      case 224:
          InitSponge ((spongeState *) state, 1152, 448);
          break;
      case 256:
          InitSponge ((spongeState *) state, 1088, 512);
          break;
      case 384:
          InitSponge ((spongeState *) state, 832, 768);
          break;
      case 512:
          InitSponge ((spongeState *) state, 576, 1024);
          break;
      default:
          return BAD_HASHLEN;
      }
    state->fixedOutputLength = hashbitlen;
    return SUCCESS;
}

/*
  * Function to give input data for the sponge function to absorb.
  * @param  state       Pointer to the state of the sponge function initialized by Init().
  * @param  data        Pointer to the input data. 
  *                     When @a databitLen is not a multiple of 8, the last bits of data must be
  *                     in the most significant bits of the last byte.
  * @param  databitLen  The number of input bits provided in the input data.
  * @pre    In the previous call to Absorb(), databitLen was a multiple of 8.
  * @return SUCCESS if successful, FAIL otherwise.
  */
static HashReturn
Update (hashState * state, const BitSequence * data, DataLength databitlen)
{
    if ((databitlen % 8) == 0)
        return Absorb ((spongeState *) state, data, databitlen);
    else
      {
          HashReturn ret =
              Absorb ((spongeState *) state, data,
                      databitlen - (databitlen % 8));
          if (ret == SUCCESS)
            {
                unsigned char lastByte;
                // Align the last partial byte to the least significant bits
                lastByte = data[databitlen / 8] >> (8 - (databitlen % 8));
                return Absorb ((spongeState *) state, &lastByte,
                               databitlen % 8);
            }
          else
              return ret;
      }
}

/*
  * Function to squeeze output data from the sponge function.
  * If @a hashbitlen was not 0 in the call to Init(), the number of output bits is equal to @a hashbitlen.
  * If @a hashbitlen was 0 in the call to Init(), the output bits must be extracted using the Squeeze() function.
  * @param  state       Pointer to the state of the sponge function initialized by Init().
  * @param  hashval     Pointer to the buffer where to store the output data.
  * @return SUCCESS if successful, FAIL otherwise.
  */
static HashReturn
Final (hashState * state, BitSequence * hashval)
{
    return Squeeze (state, hashval, state->fixedOutputLength);
}

/*===========================================================================
  =      WRAPPERS                                                           =
  ===========================================================================*/
/** initialize a SHA3 context.
 *
 * @param[in] ctx (bsdsum_sha3_ctx_t*) context.
 * @param[in] sz (size_t) size of digest in bytes (32 or 64).
 * @return (bool) boolean result of operation.
 * @exception EINVAL bad input parameter.
 * @version 1.0
 */
static bool bsdsum_sha3_begin (bsdsum_sha3_ctx_t * ctx, size_t sz)
{
    if (((sz != 32) && (sz != 64)) || (Init (&ctx->state, sz * 8) != SUCCESS))
          return false;
    ctx->len = sz;
    ctx->initialized = true;
    return true;
}

void bsdsum_sha3_256_begin (bsdsum_sha3_ctx_t * ctx)
{
    bsdsum_sha3_begin (ctx, 32);
}

void bsdsum_sha3_512_begin (bsdsum_sha3_ctx_t * ctx)
{
    bsdsum_sha3_begin (ctx, 64);
}

/** update a SHA3 context.
 *
 * @param[in] ctx (bsdsum_sha3_ctx_t*) SHA3 context (started).
 * @param[in] input (unsigned char*) input data.
 * @param[in] inputLen (size_t) input data length.
 * @return (bool) boolean result of operation.
 * @exception EINVAL bad input parameter.
 * @version 1.0
 */
bool bsdsum_sha3_update (bsdsum_sha3_ctx_t * ctx,
     		             const unsigned char *data, size_t len)
{
    if ( ! ctx->initialized)
        return false;
    return (Update (&ctx->state, data, len * 8) == SUCCESS);
}

/** end SHA3 digest and output hash.
 *
 * @param[in] ctx (bsdsum_sha3_ctx_t*) SHA3 context.
 * @param[in] digest (bsdsum_sha3_hash_t*) where to store digest.
 * @return (bool) boolean result of operation.
 * @exception EINVAL bad input parameter.
 * @version 1.0
 */
static bool bsdsum_sha3_end (bsdsum_sha3_ctx_t * ctx, bsdsum_sha3_hash_t * digest)
{
    unsigned char *output;

    if ( ! ctx->initialized)
        return false;
    if (ctx->len == 32)
        output = digest->dg256;
    else if (ctx->len == 64)
        output = digest->dg512;
    else
        return false;
    return (Final (&ctx->state, output) == SUCCESS);
}

void bsdsum_sha3_final (unsigned char *dg, bsdsum_sha3_ctx_t *ctx)
{
    bsdsum_sha3_hash_t h = { 0 };
    bsdsum_sha3_end (ctx, &h);
    if (ctx->len == 32)
        memcpy (dg, h.dg256, 32);
    else
        memcpy (dg, h.dg512, 64);
}


