/*
 * Copyright (c) 2022-2023
 *      Nicolas Provost <dev AT npsoft DOT fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include "bsdsum.h"

bsdsum_op_t bsdsum_ops[] = {
	{
		"SIZE", 16, STYLE_TXT | STYLE_NOSPLIT | STYLE_FIXED,
		(op_init_t)bsdsum_size_init,
		(op_update_t)bsdsum_size_update,
		(op_final_t)bsdsum_size_final,
	},
	{
		"MD5", MD5_DIGEST_LENGTH, STYLE_ANY,
		(op_init_t)MD5_Init,
		(op_update_t)MD5_Update,
		(op_final_t)MD5_Final,
	},
	{
		"SHA1", SHA_DIGEST_LENGTH, STYLE_ANY,
		(op_init_t)SHA1_Init,
		(op_update_t)SHA1_Update,
		(op_final_t)SHA1_Final,
	},
	{
		"SHA256", SHA256_DIGEST_LENGTH, STYLE_ANY,
		(op_init_t)SHA256_Init,
		(op_update_t)SHA256_Update,
		(op_final_t)SHA256_Final,
	},
	{
		"SHA384", SHA384_DIGEST_LENGTH, STYLE_ANY,
		(op_init_t)SHA384_Init,
		(op_update_t)SHA384_Update,
		(op_final_t)SHA384_Final,
	},
	{
		"SHA512", SHA512_DIGEST_LENGTH, STYLE_ANY,
		(op_init_t)SHA512_Init,
		(op_update_t)SHA512_Update,
		(op_final_t)SHA512_Final,
	},
	{
		"SHA3-256", SHA256_DIGEST_LENGTH, STYLE_BSD,
		(op_init_t)bsdsum_sha3_256_begin,
		(op_update_t)bsdsum_sha3_update,
		(op_final_t)bsdsum_sha3_final,
	},
	{
		"SHA3-512", SHA512_DIGEST_LENGTH, STYLE_BSD,
		(op_init_t)bsdsum_sha3_512_begin,
		(op_update_t)bsdsum_sha3_update,
		(op_final_t)bsdsum_sha3_final,
	},
	{
		"WHIRLPOOL", WHIRLPOOL_DIGEST_LEN, STYLE_BSD,
		(op_init_t)rhash_whirlpool_init,
		(op_update_t)rhash_whirlpool_update,
		(op_final_t)rhash_whirlpool_final,
	},
	{
		"BLAKE224", BLAKE224_DIGEST_LEN, STYLE_BSD,
		(op_init_t)blake224_init,
		(op_update_t)blake224_update,
		(op_final_t)blake224_final,
	},
	{
		"BLAKE256", BLAKE256_DIGEST_LEN, STYLE_BSD,
		(op_init_t)blake256_init,
		(op_update_t)blake256_update,
		(op_final_t)blake256_final,
	},
	{
		"BLAKE384", BLAKE384_DIGEST_LEN, STYLE_BSD,
		(op_init_t)blake384_init,
		(op_update_t)blake384_update,
		(op_final_t)blake384_final,
	},
	{
		"BLAKE512", BLAKE512_DIGEST_LEN, STYLE_BSD,
		(op_init_t)blake512_init,
		(op_update_t)blake512_update,
		(op_final_t)blake512_final,
	},
	{
		"BLAKE3", BLAKE3_OUT_LEN, STYLE_BSD,
		(op_init_t)blake3_hasher_init,
		(op_update_t)blake3_hasher_update,
		(op_final_t)blake3_final,
	},
	{
		"BLAKE2B", BLAKE2B_OUTBYTES, STYLE_BSD,
		(op_init_t)blake2b_start,
		(op_update_t)blake2b_update,
		(op_final_t)blake2b_end,
	},
	{
		"BLAKE2S", BLAKE2S_OUTBYTES, STYLE_BSD,
		(op_init_t)blake2s_start,
		(op_update_t)blake2s_update,
		(op_final_t)blake2s_end,
	},
	{
		NULL, 0, 0, NULL,
	}
};

bsdsum_op_t* bsdsum_op_get (const char* name)
{
	int i;

	for (i = 0; bsdsum_ops[i].name; i++)
	{
		if (strcasecmp (bsdsum_ops[i].name, name) == 0)
			return &bsdsum_ops[i];
	}
	return NULL;
}

/* Parse one algorithm name 'cp'. Returns NULL on error. 
 * If 'style' is not STYLE_NONE, check that the algorithm
 * that was found supports this style of output. */
bsdsum_op_t* bsdsum_op_find_alg (const char *cp, 
					bsdsum_style_t style,
					int quiet)
{
	bsdsum_op_t *hf;
	char *p;
	char *endptr;
	long l = 0;

	p = strchr(cp, ':');
	if (p) {
		*p++ = '\0';
		l = strtol(p, &endptr, 10);
		if ((endptr && *endptr) || 
			(l <= 1) || (l > MAX_SPLIT)) {
			bsdsum_log(LL_WARN,  "bad algorithm name \"%s:%s\"", cp, p);
			return NULL;
		}
	}

	hf = bsdsum_op_get(cp);
	if (hf == NULL || hf->name == NULL) {
		if ( ! quiet)
			bsdsum_log(LL_WARN, "unknown algorithm \"%s\"", cp);
		return NULL;
	}
	if ((hf->use_style & STYLE_NOSPLIT) && l) {
		if ( ! quiet)
			bsdsum_log(LL_WARN, "algorithm \"%s\" does not support split", cp);
		return NULL;
	}
	if ((style != STYLE_NONE) && ! (hf->use_style & STYLE_FIXED)) {
		if ((hf->use_style & style) != style) {
			if ( ! quiet)
				bsdsum_log(LL_WARN, "%s doesn't support given style", 
					hf->name);
			return NULL;
		}
	}
	hf->split = (int) l;
	return hf;
}

/* Returns true if the given style use a case sensitive
 * comparison. */
bool bsdsum_op_case_sensitive(bsdsum_style_t st)
{
	if (st & STYLE_B64)
		return true;

	return false;
}

/* find the first function having STYLE_GNU or STYLE_CKSUM flag 
 * whose output length is 'len'. */
bsdsum_op_t* bsdsum_op_for_length(size_t len)
{
	int i;

	for (i = 0; bsdsum_ops[i].name; i++) {
		if ( ! (bsdsum_ops[i].use_style & 
				(STYLE_CKSUM | STYLE_GNU)))
			continue;
		if (len == bsdsum_ops[i].digestlen * 2)
			return &bsdsum_ops[i];
	}
	return NULL;
}

