/*
   BLAKE reference C implementation

   Copyright (c) 2012 Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
#include "blake.h"


void blake224_compress( blake224_ctx *S, const uint8_t *block )
{
  uint32_t v[16], m[16], i;
#define ROT(x,n) (((x)<<(32-n))|( (x)>>(n)))
#define G(a,b,c,d,e)          \
  v[a] += (m[sigma[i][e]] ^ u256[sigma[i][e+1]]) + v[b]; \
  v[d] = ROT( v[d] ^ v[a],16);        \
  v[c] += v[d];           \
  v[b] = ROT( v[b] ^ v[c],12);        \
  v[a] += (m[sigma[i][e+1]] ^ u256[sigma[i][e]])+v[b]; \
  v[d] = ROT( v[d] ^ v[a], 8);        \
  v[c] += v[d];           \
  v[b] = ROT( v[b] ^ v[c], 7);

  for( i = 0; i < 16; ++i )  m[i] = U8TO32_BIG( block + i * 4 );

  for( i = 0; i < 8; ++i )  v[i] = S->h[i];

  v[ 8] = S->s[0] ^ u256[0];
  v[ 9] = S->s[1] ^ u256[1];
  v[10] = S->s[2] ^ u256[2];
  v[11] = S->s[3] ^ u256[3];
  v[12] = u256[4];
  v[13] = u256[5];
  v[14] = u256[6];
  v[15] = u256[7];

  /* don't xor t when the block is only padding */
  if ( !S->nullt )
  {
    v[12] ^= S->t[0];
    v[13] ^= S->t[0];
    v[14] ^= S->t[1];
    v[15] ^= S->t[1];
  }

  for( i = 0; i < 14; ++i )
  {
    /* column step */
    G( 0,  4,  8, 12,  0 );
    G( 1,  5,  9, 13,  2 );
    G( 2,  6, 10, 14,  4 );
    G( 3,  7, 11, 15,  6 );
    /* diagonal step */
    G( 0,  5, 10, 15,  8 );
    G( 1,  6, 11, 12, 10 );
    G( 2,  7,  8, 13, 12 );
    G( 3,  4,  9, 14, 14 );
  }

  for( i = 0; i < 16; ++i )  S->h[i % 8] ^= v[i];

  for( i = 0; i < 8 ; ++i )  S->h[i] ^= S->s[i % 4];
}


void blake224_init( blake224_ctx *S )
{
  S->h[0] = 0xc1059ed8;
  S->h[1] = 0x367cd507;
  S->h[2] = 0x3070dd17;
  S->h[3] = 0xf70e5939;
  S->h[4] = 0xffc00b31;
  S->h[5] = 0x68581511;
  S->h[6] = 0x64f98fa7;
  S->h[7] = 0xbefa4fa4;
  S->t[0] = S->t[1] = S->buflen = S->nullt = 0;
  S->s[0] = S->s[1] = S->s[2] = S->s[3] = 0;
}


void blake224_process( blake224_ctx *S, const uint8_t *in, uint64_t inlen )
{
  int left = S->buflen;
  int fill = 64 - left;

  /* data left and data received fill a block  */
  if( left && ( inlen >= fill ) )
  {
    memcpy( ( void * ) ( S->buf + left ), ( void * ) in, fill );
    S->t[0] += 512;

    if ( S->t[0] == 0 ) S->t[1]++;

    blake224_compress( S, S->buf );
    in += fill;
    inlen  -= fill;
    left = 0;
  }

  /* compress blocks of data received */
  while( inlen >= 64 )
  {
    S->t[0] += 512;

    if ( S->t[0] == 0 ) S->t[1]++;

    blake224_compress( S, in );
    in += 64;
    inlen -= 64;
  }

  /* store any data left */
  if( inlen > 0 )
  {
    memcpy( ( void * ) ( S->buf + left ), \
            ( void * ) in, ( size_t ) inlen );
    S->buflen = left + ( int )inlen;
  }
  else S->buflen = 0;
}


void blake224_end( blake224_ctx *S, uint8_t *out )
{
  uint8_t msglen[8], zz = 0x00, oz = 0x80;
  uint32_t lo = S->t[0] + ( S->buflen << 3 ), hi = S->t[1];

  /* support for hashing more than 2^32 bits */
  if ( lo < ( S->buflen << 3 ) ) hi++;

  U32TO8_BIG(  msglen + 0, hi );
  U32TO8_BIG(  msglen + 4, lo );

  if ( S->buflen == 55 )   /* one padding byte */
  {
    S->t[0] -= 8;
    blake224_process( S, &oz, 1 );
  }
  else
  {
    if ( S->buflen < 55 )   /* enough space to fill the block  */
    {
      if ( !S->buflen ) S->nullt = 1;

      S->t[0] -= 440 - ( S->buflen << 3 );
      blake224_process( S, padding, 55 - S->buflen );
    }
    else   /* need 2 compressions */
    {
      S->t[0] -= 512 - ( S->buflen << 3 );
      blake224_process( S, padding, 64 - S->buflen );
      S->t[0] -= 440;
      blake224_process( S, padding + 1, 55 );
      S->nullt = 1;
    }

    blake224_process( S, &zz, 1 );
    S->t[0] -= 8;
  }

  S->t[0] -= 64;
  blake224_process( S, msglen, 8 );
  U32TO8_BIG( out + 0, S->h[0] );
  U32TO8_BIG( out + 4, S->h[1] );
  U32TO8_BIG( out + 8, S->h[2] );
  U32TO8_BIG( out + 12, S->h[3] );
  U32TO8_BIG( out + 16, S->h[4] );
  U32TO8_BIG( out + 20, S->h[5] );
  U32TO8_BIG( out + 24, S->h[6] );
}


void blake224_hash( uint8_t *out, const uint8_t *in, uint64_t inlen )
{
  blake224_ctx S;
  blake224_init( &S );
  blake224_process( &S, in, inlen );
  blake224_end( &S, out );
}


int blake224_test()
{
  int i, v;
  uint8_t in[72], out[28];
  uint8_t test1[] =
  {
    0x45, 0x04, 0xcb, 0x03, 0x14, 0xfb, 0x2a, 0x4f,
    0x7a, 0x69, 0x2e, 0x69, 0x6e, 0x48, 0x79, 0x12,
    0xfe, 0x3f, 0x24, 0x68, 0xfe, 0x31, 0x2c, 0x73,
    0xa5, 0x27, 0x8e, 0xc5
  };
  uint8_t test2[] =
  {
    0xf5, 0xaa, 0x00, 0xdd, 0x1c, 0xb8, 0x47, 0xe3,
    0x14, 0x03, 0x72, 0xaf, 0x7b, 0x5c, 0x46, 0xb4,
    0x88, 0x8d, 0x82, 0xc8, 0xc0, 0xa9, 0x17, 0x91,
    0x3c, 0xfb, 0x5d, 0x04
  };
  memset( in, 0, 72 );
  blake224_hash( out, in, 1 );
  v = 0;

  for( i = 0; i < 28; ++i )
  {
    if ( out[i] != test1[i] ) v = 1;
  }

  if ( v ) printf( "test 1 error\n" );

  blake224_hash( out, in, 72 );

  for( i = 0; i < 28; ++i )
  {
    if ( out[i] != test2[i] ) v = 1;
  }

  if ( v ) printf( "test 2 error\n" );
  return v;
}

void blake256_compress( blake256_ctx *S, const uint8_t *block )
{
  uint32_t v[16], m[16], i;
#define ROT32(x,n) (((x)<<(32-n))|( (x)>>(n)))
#define G32(a,b,c,d,e)          \
  v[a] += (m[sigma[i][e]] ^ u256[sigma[i][e+1]]) + v[b]; \
  v[d] = ROT32( v[d] ^ v[a],16);        \
  v[c] += v[d];           \
  v[b] = ROT32( v[b] ^ v[c],12);        \
  v[a] += (m[sigma[i][e+1]] ^ u256[sigma[i][e]])+v[b]; \
  v[d] = ROT32( v[d] ^ v[a], 8);        \
  v[c] += v[d];           \
  v[b] = ROT32( v[b] ^ v[c], 7);

  for( i = 0; i < 16; ++i )  m[i] = U8TO32_BIG( block + i * 4 );

  for( i = 0; i < 8; ++i )  v[i] = S->h[i];

  v[ 8] = S->s[0] ^ u256[0];
  v[ 9] = S->s[1] ^ u256[1];
  v[10] = S->s[2] ^ u256[2];
  v[11] = S->s[3] ^ u256[3];
  v[12] = u256[4];
  v[13] = u256[5];
  v[14] = u256[6];
  v[15] = u256[7];

  /* don't xor t when the block is only padding */
  if ( !S->nullt )
  {
    v[12] ^= S->t[0];
    v[13] ^= S->t[0];
    v[14] ^= S->t[1];
    v[15] ^= S->t[1];
  }

  for( i = 0; i < 14; ++i )
  {
    /* column step */
    G32( 0,  4,  8, 12,  0 );
    G32( 1,  5,  9, 13,  2 );
    G32( 2,  6, 10, 14,  4 );
    G32( 3,  7, 11, 15,  6 );
    /* diagonal step */
    G32( 0,  5, 10, 15,  8 );
    G32( 1,  6, 11, 12, 10 );
    G32( 2,  7,  8, 13, 12 );
    G32( 3,  4,  9, 14, 14 );
  }

  for( i = 0; i < 16; ++i )  S->h[i % 8] ^= v[i];

  for( i = 0; i < 8 ; ++i )  S->h[i] ^= S->s[i % 4];
}


void blake256_init( blake256_ctx *S )
{
  S->h[0] = 0x6a09e667;
  S->h[1] = 0xbb67ae85;
  S->h[2] = 0x3c6ef372;
  S->h[3] = 0xa54ff53a;
  S->h[4] = 0x510e527f;
  S->h[5] = 0x9b05688c;
  S->h[6] = 0x1f83d9ab;
  S->h[7] = 0x5be0cd19;
  S->t[0] = S->t[1] = S->buflen = S->nullt = 0;
  S->s[0] = S->s[1] = S->s[2] = S->s[3] = 0;
}


void blake256_process( blake256_ctx *S, const uint8_t *in, uint64_t inlen )
{
  int left = S->buflen;
  int fill = 64 - left;

  /* data left and data received fill a block  */
  if( left && ( inlen >= fill ) )
  {
    memcpy( ( void * ) ( S->buf + left ), ( void * ) in, fill );
    S->t[0] += 512;

    if ( S->t[0] == 0 ) S->t[1]++;

    blake256_compress( S, S->buf );
    in += fill;
    inlen  -= fill;
    left = 0;
  }

  /* compress blocks of data received */
  while( inlen >= 64 )
  {
    S->t[0] += 512;

    if ( S->t[0] == 0 ) S->t[1]++;

    blake256_compress( S, in );
    in += 64;
    inlen -= 64;
  }

  /* store any data left */
  if( inlen > 0 )
  {
    memcpy( ( void * ) ( S->buf + left ),   \
            ( void * ) in, ( size_t ) inlen );
    S->buflen = left + ( int )inlen;
  }
  else S->buflen = 0;
}


void blake256_end( blake256_ctx *S, uint8_t *out )
{
  uint8_t msglen[8], zo = 0x01, oo = 0x81;
  uint32_t lo = S->t[0] + ( S->buflen << 3 ), hi = S->t[1];

  /* support for hashing more than 2^32 bits */
  if ( lo < ( S->buflen << 3 ) ) hi++;

  U32TO8_BIG(  msglen + 0, hi );
  U32TO8_BIG(  msglen + 4, lo );

  if ( S->buflen == 55 )   /* one padding byte */
  {
    S->t[0] -= 8;
    blake256_process( S, &oo, 1 );
  }
  else
  {
    if ( S->buflen < 55 )   /* enough space to fill the block  */
    {
      if ( !S->buflen ) S->nullt = 1;

      S->t[0] -= 440 - ( S->buflen << 3 );
      blake256_process( S, padding, 55 - S->buflen );
    }
    else   /* need 2 compressions */
    {
      S->t[0] -= 512 - ( S->buflen << 3 );
      blake256_process( S, padding, 64 - S->buflen );
      S->t[0] -= 440;
      blake256_process( S, padding + 1, 55 );
      S->nullt = 1;
    }

    blake256_process( S, &zo, 1 );
    S->t[0] -= 8;
  }

  S->t[0] -= 64;
  blake256_process( S, msglen, 8 );
  U32TO8_BIG( out + 0, S->h[0] );
  U32TO8_BIG( out + 4, S->h[1] );
  U32TO8_BIG( out + 8, S->h[2] );
  U32TO8_BIG( out + 12, S->h[3] );
  U32TO8_BIG( out + 16, S->h[4] );
  U32TO8_BIG( out + 20, S->h[5] );
  U32TO8_BIG( out + 24, S->h[6] );
  U32TO8_BIG( out + 28, S->h[7] );
}


void blake256_hash( uint8_t *out, const uint8_t *in, uint64_t inlen )
{
  blake256_ctx S;
  blake256_init( &S );
  blake256_process( &S, in, inlen );
  blake256_end( &S, out );
}


int blake256_test()
{
  int i, v;
  uint8_t in[72], out[32];
  uint8_t test1[] =
  {
    0x0c, 0xe8, 0xd4, 0xef, 0x4d, 0xd7, 0xcd, 0x8d,
    0x62, 0xdf, 0xde, 0xd9, 0xd4, 0xed, 0xb0, 0xa7,
    0x74, 0xae, 0x6a, 0x41, 0x92, 0x9a, 0x74, 0xda,
    0x23, 0x10, 0x9e, 0x8f, 0x11, 0x13, 0x9c, 0x87
  };
  uint8_t test2[] =
  {
    0xd4, 0x19, 0xba, 0xd3, 0x2d, 0x50, 0x4f, 0xb7,
    0xd4, 0x4d, 0x46, 0x0c, 0x42, 0xc5, 0x59, 0x3f,
    0xe5, 0x44, 0xfa, 0x4c, 0x13, 0x5d, 0xec, 0x31,
    0xe2, 0x1b, 0xd9, 0xab, 0xdc, 0xc2, 0x2d, 0x41
  };
  memset( in, 0, 72 );
  blake256_hash( out, in, 1 );
  v = 0;

  for( i = 0; i < 32; ++i )
  {
    if ( out[i] != test1[i] ) v = 1;
  }

  if ( v ) printf( "test 1 error\n" );

  blake256_hash( out, in, 72 );

  for( i = 0; i < 32; ++i )
  {
    if ( out[i] != test2[i] ) v = 1;
  }

  if ( v ) printf( "test 2 error\n" );
  return v;
}

void blake384_compress( blake384_ctx *S, const uint8_t *block )
{
  uint64_t v[16], m[16], i;
#define ROT64(x,n) (((x)<<(64-n))|( (x)>>(n)))
#define G64(a,b,c,d,e)          \
  v[a] += (m[sigma[i][e]] ^ u512[sigma[i][e+1]]) + v[b];\
  v[d] = ROT64( v[d] ^ v[a],32);        \
  v[c] += v[d];           \
  v[b] = ROT64( v[b] ^ v[c],25);        \
  v[a] += (m[sigma[i][e+1]] ^ u512[sigma[i][e]])+v[b];  \
  v[d] = ROT64( v[d] ^ v[a],16);        \
  v[c] += v[d];           \
  v[b] = ROT64( v[b] ^ v[c],11);

  for( i = 0; i < 16; ++i )  m[i] = U8TO64_BIG( block + i * 8 );

  for( i = 0; i < 8; ++i )  v[i] = S->h[i];

  v[ 8] = S->s[0] ^ u512[0];
  v[ 9] = S->s[1] ^ u512[1];
  v[10] = S->s[2] ^ u512[2];
  v[11] = S->s[3] ^ u512[3];
  v[12] =  u512[4];
  v[13] =  u512[5];
  v[14] =  u512[6];
  v[15] =  u512[7];

  /* don't xor t when the block is only padding */
  if ( !S->nullt )
  {
    v[12] ^= S->t[0];
    v[13] ^= S->t[0];
    v[14] ^= S->t[1];
    v[15] ^= S->t[1];
  }

  for( i = 0; i < 16; ++i )
  {
    /* column step */
    G64( 0, 4, 8, 12, 0 );
    G64( 1, 5, 9, 13, 2 );
    G64( 2, 6, 10, 14, 4 );
    G64( 3, 7, 11, 15, 6 );
    /* diagonal step */
    G64( 0, 5, 10, 15, 8 );
    G64( 1, 6, 11, 12, 10 );
    G64( 2, 7, 8, 13, 12 );
    G64( 3, 4, 9, 14, 14 );
  }

  for( i = 0; i < 16; ++i )  S->h[i % 8] ^= v[i];

  for( i = 0; i < 8 ; ++i )  S->h[i] ^= S->s[i % 4];
}


void blake384_init( blake384_ctx *S )
{
  S->h[0] = 0xcbbb9d5dc1059ed8ULL;
  S->h[1] = 0x629a292a367cd507ULL;
  S->h[2] = 0x9159015a3070dd17ULL;
  S->h[3] = 0x152fecd8f70e5939ULL;
  S->h[4] = 0x67332667ffc00b31ULL;
  S->h[5] = 0x8eb44a8768581511ULL;
  S->h[6] = 0xdb0c2e0d64f98fa7ULL;
  S->h[7] = 0x47b5481dbefa4fa4ULL;
  S->t[0] = S->t[1] = S->buflen = S->nullt = 0;
  S->s[0] = S->s[1] = S->s[2] = S->s[3] = 0;
}


void blake384_process( blake384_ctx *S, const uint8_t *in, uint64_t inlen )
{
  int left = S->buflen;
  int fill = 128 - left;

  /* data left and data received fill a block  */
  if( left && ( inlen >= fill ) )
  {
    memcpy( ( void * ) ( S->buf + left ), ( void * ) in, fill );
    S->t[0] += 1024;

    if ( S->t[0] == 0 ) S->t[1]++;

    blake384_compress( S, S->buf );
    in += fill;
    inlen  -= fill;
    left = 0;
  }

  /* compress blocks of data received */
  while( inlen >= 128 )
  {
    S->t[0] += 1024;

    if ( S->t[0] == 0 ) S->t[1]++;

    blake384_compress( S, in );
    in += 128;
    inlen -= 128;
  }

  /* store any data left */
  if( inlen > 0 )
  {
    memcpy( ( void * ) ( S->buf + left ), \
            ( void * ) in, ( size_t ) inlen );
    S->buflen = left + ( int )inlen;
  }
  else S->buflen = 0;
}


void blake384_end( blake384_ctx *S, uint8_t *out )
{
  uint8_t msglen[16], zz = 0x00, oz = 0x80;
  uint64_t lo = S->t[0] + ( S->buflen << 3 ), hi = S->t[1];

  /* support for hashing more than 2^32 bits */
  if ( lo < ( S->buflen << 3 ) ) hi++;

  U64TO8_BIG(  msglen + 0, hi );
  U64TO8_BIG(  msglen + 8, lo );

  if ( S->buflen == 111 )   /* one padding byte */
  {
    S->t[0] -= 8;
    blake384_process( S, &oz, 1 );
  }
  else
  {
    if ( S->buflen < 111 )  /* enough space to fill the block */
    {
      if ( !S->buflen ) S->nullt = 1;

      S->t[0] -= 888 - ( S->buflen << 3 );
      blake384_process( S, padding, 111 - S->buflen );
    }
    else   /* need 2 compressions */
    {
      S->t[0] -= 1024 - ( S->buflen << 3 );
      blake384_process( S, padding, 128 - S->buflen );
      S->t[0] -= 888;
      blake384_process( S, padding + 1, 111 );
      S->nullt = 1;
    }

    blake384_process( S, &zz, 1 );
    S->t[0] -= 8;
  }

  S->t[0] -= 128;
  blake384_process( S, msglen, 16 );
  U64TO8_BIG( out + 0, S->h[0] );
  U64TO8_BIG( out + 8, S->h[1] );
  U64TO8_BIG( out + 16, S->h[2] );
  U64TO8_BIG( out + 24, S->h[3] );
  U64TO8_BIG( out + 32, S->h[4] );
  U64TO8_BIG( out + 40, S->h[5] );
}


void blake384_hash( uint8_t *out, const uint8_t *in, uint64_t inlen )
{
  blake384_ctx S;
  blake384_init( &S );
  blake384_process( &S, in, inlen );
  blake384_end( &S, out );
}


int blake384_test()
{
  int i, v;
  uint8_t in[144], out[48];
  uint8_t test1[] =
  {
    0x10, 0x28, 0x1f, 0x67, 0xe1, 0x35, 0xe9, 0x0a, 0xe8, 0xe8, 0x82, 0x25, 0x1a, 0x35, 0x55, 0x10,
    0xa7, 0x19, 0x36, 0x7a, 0xd7, 0x02, 0x27, 0xb1, 0x37, 0x34, 0x3e, 0x1b, 0xc1, 0x22, 0x01, 0x5c,
    0x29, 0x39, 0x1e, 0x85, 0x45, 0xb5, 0x27, 0x2d, 0x13, 0xa7, 0xc2, 0x87, 0x9d, 0xa3, 0xd8, 0x07
  };
  uint8_t test2[] =
  {
    0x0b, 0x98, 0x45, 0xdd, 0x42, 0x95, 0x66, 0xcd, 0xab, 0x77, 0x2b, 0xa1, 0x95, 0xd2, 0x71, 0xef,
    0xfe, 0x2d, 0x02, 0x11, 0xf1, 0x69, 0x91, 0xd7, 0x66, 0xba, 0x74, 0x94, 0x47, 0xc5, 0xcd, 0xe5,
    0x69, 0x78, 0x0b, 0x2d, 0xaa, 0x66, 0xc4, 0xb2, 0x24, 0xa2, 0xec, 0x2e, 0x5d, 0x09, 0x17, 0x4c
  };
  memset( in, 0, 144 );
  blake384_hash( out, in, 1 );
  v = 0;

  for( i = 0; i < 48; ++i )
  {
    if ( out[i] != test1[i] ) v = 1;
  }

  if ( v ) printf( "test 1 error\n" );

  blake384_hash( out, in, 144 );

  for( i = 0; i < 48; ++i )
  {
    if ( out[i] != test2[i] ) v = 1;
  }

  if ( v ) printf( "test 2 error\n" );
  return v;
}

void blake512_compress( blake512_ctx *S, const uint8_t *block )
{
  uint64_t v[16], m[16], i; 

  for( i = 0; i < 16; ++i )  m[i] = U8TO64_BIG( block + i * 8 );

  for( i = 0; i < 8; ++i )  v[i] = S->h[i];

  v[ 8] = S->s[0] ^ u512[0];
  v[ 9] = S->s[1] ^ u512[1];
  v[10] = S->s[2] ^ u512[2];
  v[11] = S->s[3] ^ u512[3];
  v[12] =  u512[4];
  v[13] =  u512[5];
  v[14] =  u512[6];
  v[15] =  u512[7];

  /* don't xor t when the block is only padding */
  if ( !S->nullt )
  {
    v[12] ^= S->t[0];
    v[13] ^= S->t[0];
    v[14] ^= S->t[1];
    v[15] ^= S->t[1];
  }

  for( i = 0; i < 16; ++i )
  {
    /* column step */
    G64( 0, 4, 8, 12, 0 );
    G64( 1, 5, 9, 13, 2 );
    G64( 2, 6, 10, 14, 4 );
    G64( 3, 7, 11, 15, 6 );
    /* diagonal step */
    G64( 0, 5, 10, 15, 8 );
    G64( 1, 6, 11, 12, 10 );
    G64( 2, 7, 8, 13, 12 );
    G64( 3, 4, 9, 14, 14 );
  }

  for( i = 0; i < 16; ++i )  S->h[i % 8] ^= v[i];

  for( i = 0; i < 8 ; ++i )  S->h[i] ^= S->s[i % 4];
}


void blake512_init( blake512_ctx *S )
{
  S->h[0] = 0x6a09e667f3bcc908ULL;
  S->h[1] = 0xbb67ae8584caa73bULL;
  S->h[2] = 0x3c6ef372fe94f82bULL;
  S->h[3] = 0xa54ff53a5f1d36f1ULL;
  S->h[4] = 0x510e527fade682d1ULL;
  S->h[5] = 0x9b05688c2b3e6c1fULL;
  S->h[6] = 0x1f83d9abfb41bd6bULL;
  S->h[7] = 0x5be0cd19137e2179ULL;
  S->t[0] = S->t[1] = S->buflen = S->nullt = 0;
  S->s[0] = S->s[1] = S->s[2] = S->s[3] = 0;
}


void blake512_process( blake512_ctx *S, const uint8_t *in, uint64_t inlen )
{
  int left = S->buflen;
  int fill = 128 - left;

  /* data left and data received fill a block  */
  if( left && ( inlen >= fill ) )
  {
    memcpy( ( void * ) ( S->buf + left ), ( void * ) in, fill );
    S->t[0] += 1024;

    if ( S->t[0] == 0 ) S->t[1]++;

    blake512_compress( S, S->buf );
    in += fill;
    inlen  -= fill;
    left = 0;
  }

  /* compress blocks of data received */
  while( inlen >= 128 )
  {
    S->t[0] += 1024;

    if ( S->t[0] == 0 ) S->t[1]++;

    blake512_compress( S, in );
    in += 128;
    inlen -= 128;
  }

  /* store any data left */
  if( inlen > 0 )
  {
    memcpy( ( void * ) ( S->buf + left ),   \
            ( void * ) in, ( size_t ) inlen );
    S->buflen = left + ( int )inlen;
  }
  else S->buflen = 0;
}


void blake512_end( blake512_ctx *S, uint8_t *out )
{
  uint8_t msglen[16], zo = 0x01, oo = 0x81;
  uint64_t lo = S->t[0] + ( S->buflen << 3 ), hi = S->t[1];

  /* support for hashing more than 2^32 bits */
  if ( lo < ( S->buflen << 3 ) ) hi++;

  U64TO8_BIG(  msglen + 0, hi );
  U64TO8_BIG(  msglen + 8, lo );

  if ( S->buflen == 111 )   /* one padding byte */
  {
    S->t[0] -= 8;
    blake512_process( S, &oo, 1 );
  }
  else
  {
    if ( S->buflen < 111 )  /* enough space to fill the block */
    {
      if ( !S->buflen ) S->nullt = 1;

      S->t[0] -= 888 - ( S->buflen << 3 );
      blake512_process( S, padding, 111 - S->buflen );
    }
    else   /* need 2 compressions */
    {
      S->t[0] -= 1024 - ( S->buflen << 3 );
      blake512_process( S, padding, 128 - S->buflen );
      S->t[0] -= 888;
      blake512_process( S, padding + 1, 111 );
      S->nullt = 1;
    }

    blake512_process( S, &zo, 1 );
    S->t[0] -= 8;
  }

  S->t[0] -= 128;
  blake512_process( S, msglen, 16 );
  U64TO8_BIG( out + 0, S->h[0] );
  U64TO8_BIG( out + 8, S->h[1] );
  U64TO8_BIG( out + 16, S->h[2] );
  U64TO8_BIG( out + 24, S->h[3] );
  U64TO8_BIG( out + 32, S->h[4] );
  U64TO8_BIG( out + 40, S->h[5] );
  U64TO8_BIG( out + 48, S->h[6] );
  U64TO8_BIG( out + 56, S->h[7] );
}


void blake512_hash( uint8_t *out, const uint8_t *in, uint64_t inlen )
{
  blake512_ctx S;
  blake512_init( &S );
  blake512_process( &S, in, inlen );
  blake512_end( &S, out );
}


int blake512_test()
{
  int i, v;
  uint8_t in[144], out[64];
  uint8_t test1[] =
  {
    0x97, 0x96, 0x15, 0x87, 0xf6, 0xd9, 0x70, 0xfa, 0xba, 0x6d, 0x24, 0x78, 0x04, 0x5d, 0xe6, 0xd1,
    0xfa, 0xbd, 0x09, 0xb6, 0x1a, 0xe5, 0x09, 0x32, 0x05, 0x4d, 0x52, 0xbc, 0x29, 0xd3, 0x1b, 0xe4,
    0xff, 0x91, 0x02, 0xb9, 0xf6, 0x9e, 0x2b, 0xbd, 0xb8, 0x3b, 0xe1, 0x3d, 0x4b, 0x9c, 0x06, 0x09,
    0x1e, 0x5f, 0xa0, 0xb4, 0x8b, 0xd0, 0x81, 0xb6, 0x34, 0x05, 0x8b, 0xe0, 0xec, 0x49, 0xbe, 0xb3
  };
  uint8_t test2[] =
  {
    0x31, 0x37, 0x17, 0xd6, 0x08, 0xe9, 0xcf, 0x75, 0x8d, 0xcb, 0x1e, 0xb0, 0xf0, 0xc3, 0xcf, 0x9f,
    0xC1, 0x50, 0xb2, 0xd5, 0x00, 0xfb, 0x33, 0xf5, 0x1c, 0x52, 0xaf, 0xc9, 0x9d, 0x35, 0x8a, 0x2f,
    0x13, 0x74, 0xb8, 0xa3, 0x8b, 0xba, 0x79, 0x74, 0xe7, 0xf6, 0xef, 0x79, 0xca, 0xb1, 0x6f, 0x22,
    0xCE, 0x1e, 0x64, 0x9d, 0x6e, 0x01, 0xad, 0x95, 0x89, 0xc2, 0x13, 0x04, 0x5d, 0x54, 0x5d, 0xde
  };
  memset( in, 0, 144 );
  blake512_hash( out, in, 1 );
  v = 0;

  for( i = 0; i < 64; ++i )
  {
    if ( out[i] != test1[i] ) v = 1;
  }

  if ( v ) printf( "test 1 error\n" );

  blake512_hash( out, in, 144 );

  for( i = 0; i < 64; ++i )
  {
    if ( out[i] != test2[i] ) v = 1;
  }

  if ( v ) printf( "test 2 error\n" );
  return v;
}

