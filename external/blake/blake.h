/*
   BLAKE reference C implementation

   Copyright (c) 2012 Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef __BLAKE_H
#define __BLAKE_H

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define BLAKE224_DIGEST_LEN 28
#define BLAKE256_DIGEST_LEN 32
#define BLAKE384_DIGEST_LEN 48
#define BLAKE512_DIGEST_LEN 64

#define U8TO32_BIG(p)					      \
  (((uint32_t)((p)[0]) << 24) | ((uint32_t)((p)[1]) << 16) |  \
   ((uint32_t)((p)[2]) <<  8) | ((uint32_t)((p)[3])      ))

#define U32TO8_BIG(p, v)				        \
  (p)[0] = (uint8_t)((v) >> 24); (p)[1] = (uint8_t)((v) >> 16); \
  (p)[2] = (uint8_t)((v) >>  8); (p)[3] = (uint8_t)((v)      );

#define U8TO64_BIG(p) \
  (((uint64_t)U8TO32_BIG(p) << 32) | (uint64_t)U8TO32_BIG((p) + 4))

#define U64TO8_BIG(p, v)		      \
  U32TO8_BIG((p),     (uint32_t)((v) >> 32)); \
  U32TO8_BIG((p) + 4, (uint32_t)((v)      ));

typedef struct
{
  uint32_t h[8], s[4], t[2];
  int buflen, nullt;
  uint8_t  buf[64];
} blake256_ctx;

typedef blake256_ctx blake224_ctx;

typedef struct
{
  uint64_t h[8], s[4], t[2];
  int buflen, nullt;
  uint8_t buf[128]; 
} blake512_ctx;

typedef blake512_ctx blake384_ctx;

static const uint8_t sigma[][16] =
{
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
  {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
  { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
  { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
  {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
  {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
  { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
  {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13 , 0 },
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
  {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
  { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
  { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 }
};

static const uint32_t u256[16] =
{
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
  0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
  0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
  0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
};

static const uint64_t u512[16] =
{
  0x243f6a8885a308d3ULL, 0x13198a2e03707344ULL, 
  0xa4093822299f31d0ULL, 0x082efa98ec4e6c89ULL,
  0x452821e638d01377ULL, 0xbe5466cf34e90c6cULL, 
  0xc0ac29b7c97c50ddULL, 0x3f84d5b5b5470917ULL,
  0x9216d5d98979fb1bULL, 0xd1310ba698dfb5acULL, 
  0x2ffd72dbd01adfb7ULL, 0xb8e1afed6a267e96ULL,
  0xba7c9045f12c7f99ULL, 0x24a19947b3916cf7ULL, 
  0x0801f2e2858efc16ULL, 0x636920d871574e69ULL
};


static const uint8_t padding[129] =
{
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};


void blake224_compress(blake224_ctx *S, const uint8_t *block);
void blake224_init(blake224_ctx *S);
void blake224_process(blake224_ctx *S, const uint8_t *in, uint64_t inlen);
static inline void blake224_update(blake224_ctx *S, 
					const unsigned char *buf, 
					size_t len)
{
	blake224_process(S, buf, len);
}
void blake224_end(blake224_ctx *S, uint8_t *out);
static inline void blake224_final(unsigned char *out, blake224_ctx *S)
{
	blake224_end(S, out);
}
int blake224_test();

void blake256_compress(blake256_ctx *S, const uint8_t *block);
void blake256_init(blake256_ctx *S);
void blake256_process(blake256_ctx *S, const uint8_t *in, uint64_t inlen);
static inline void blake256_update(blake256_ctx *S, 
					const unsigned char *buf, 
					size_t len)
{
	blake256_process(S, buf, len);
}
void blake256_end(blake256_ctx *S, uint8_t *out);
static inline void blake256_final(unsigned char *out, blake256_ctx *S)
{
	blake256_end(S, out);
}
int blake256_test();

void blake384_compress(blake384_ctx *S, const uint8_t *block);
void blake384_init(blake384_ctx *S);
void blake384_process(blake384_ctx *S, const uint8_t *in, uint64_t inlen);
static inline void blake384_update(blake384_ctx *S, 
					const unsigned char *buf, 
					size_t len)
{
	blake384_process(S, buf, len);
}
void blake384_end(blake384_ctx *S, uint8_t *out);
static inline void blake384_final(unsigned char *out, blake384_ctx *S)
{
	blake384_end(S, out);
}
int blake384_test();

void blake512_compress(blake512_ctx *S, const uint8_t *block);
void blake512_init(blake512_ctx *S);
void blake512_process(blake512_ctx *S, const uint8_t *in, uint64_t inlen);
static inline void blake512_update(blake512_ctx *S, 
					const unsigned char *buf, 
					size_t len)
{
	blake512_process(S, buf, len);
}
void blake512_end(blake512_ctx *S, uint8_t *out);
static inline void blake512_final(unsigned char *out, blake512_ctx *S)
{
	blake512_end(S, out);
}
int blake512_test();

#endif

