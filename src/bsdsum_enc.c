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
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "bsdsum.h"

static const char *set_mix = "=^2Bf0F+5K|:4q9!<>$S@Tt%WZz-?[]_";

/* get the n-th bit into 'data' */
static int bsdsum_enc_bit (int n, const unsigned char *data)
{
	unsigned char c;
	const unsigned char b[] = { 1, 2, 4, 8, 16, 32, 64, 128 };

	c = data[n / 8];
	return (c & b[n % 8]) ? 1 : 0;
}

/* encode 'data' using the set of 32 characters 'set'.
 * 5-bit encoding: blocks of 32 bits, 4 bytes <> 6 chars + 2 bits.
 * input (bits) | output (chars)
 * 224          | 44:+ = 45
 * 256          | 51+ = 52
 * 384          | 7:6+ = 77
 * 512          | 102+ = 103
 */
char* bsdsum_enc_32 (const unsigned char *data, size_t len,
			bsdsum_set32_t nset, size_t *olen)
{
	char *out;
	int i, j, n;
	                    /* 0123456789abcdef0123456789abcdef */
	const char *set;

	switch(nset) {
		case SET32_MIX:
			set = set_mix;
			break;
		default:
			*olen = 0;
			return NULL;
	}

	switch(8*len) {
		case 128:
			*olen = 26;
			break;
		case 224:
			*olen = 45;
			break;
		case 256:
			*olen = 52;
			break;
		case 384:
			*olen = 77;
			break;
		case 512:
			*olen = 103;
			break;
		default:
			*olen = 0;
			return NULL;
	}

	out = calloc(*olen + 1, 1);
	if (out == NULL)
		bsdsum_log(LL_ERR|LL_FATAL, "out of memory");
	for (i = 0, n = 0; i < 8*len; i += 5, n++) {
		unsigned char c = 0;
		int max;

		if (i+4 < 8*len)
			max = 4;
		else
			max = 8*len - i - 1;
		for (j = max; j >= 0; j--) {
			c += bsdsum_enc_bit(i+j, data);
			if (j > 0)
				c <<= 1;
		}
		out[n] = set[c];
	}
	return out;
}

/* parse a string to see if it is possibly a 5-bit encoded hash.
 * 'alg_len' is the length in bytes of the digest algorithm or 0 if
 * unknown. Returns STYLE_NONE, STYLE_ERROR or STYLE_MIX32. */
bsdsum_style_t bsdsum_enc_test(const char *s,size_t alg_len)
{
	size_t len = strlen(s);
	int i;

	switch(len) {
		case 0:
			return STYLE_NONE;
		case 26:
			if (alg_len && (alg_len != 16))
				return STYLE_ERROR;
			break;
		case 45:
			if (alg_len && (alg_len != 28))
				return STYLE_ERROR;
			break;
		case 52:
			if (alg_len && (alg_len != 32))
				return STYLE_ERROR;
			break;
		case 77:
			if (alg_len && (alg_len != 48))
				return STYLE_ERROR;
			break;
		case 103:
			if (alg_len && (alg_len != 64))
				return STYLE_ERROR;
			break;
		default:
			return STYLE_NONE;
	}
	for (i = 0; i < len; i++) {
		if (strchr(set_mix, s[i]) == NULL)
			return STYLE_NONE;
	}
	return STYLE_M32;
}

