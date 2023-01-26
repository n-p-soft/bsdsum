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
		"SIZE", 16, STYLE_TEXT | STYLE_NOSPLIT,
		(op_init_t)bsdsum_size_init,
		(op_update_t)bsdsum_size_update,
		(op_final_t)bsdsum_size_final,
	},
	{
		"MD5", MD5_DIGEST_LENGTH, STYLE_SPACE,
		(op_init_t)MD5_Init,
		(op_update_t)MD5_Update,
		(op_final_t)MD5_Final,
	},
	{
		"SHA1", SHA_DIGEST_LENGTH, STYLE_SPACE,
		(op_init_t)SHA1_Init,
		(op_update_t)SHA1_Update,
		(op_final_t)SHA1_Final,
	},
	{
		"SHA256", SHA256_DIGEST_LENGTH, STYLE_SPACE,
		(op_init_t)SHA256_Init,
		(op_update_t)SHA256_Update,
		(op_final_t)SHA256_Final,
	},
	{
		"SHA384", SHA384_DIGEST_LENGTH, STYLE_SPACE,
		(op_init_t)SHA384_Init,
		(op_update_t)SHA384_Update,
		(op_final_t)SHA384_Final,
	},
	{
		"SHA512", SHA512_DIGEST_LENGTH, STYLE_SPACE,
		(op_init_t)SHA512_Init,
		(op_update_t)SHA512_Update,
		(op_final_t)SHA512_Final,
	},
	{
		"SHA3-256", SHA256_DIGEST_LENGTH, STYLE_NONE,
		(op_init_t)bsdsum_sha3_256_begin,
		(op_update_t)bsdsum_sha3_update,
		(op_final_t)bsdsum_sha3_final,
	},
	{
		"SHA3-512", SHA512_DIGEST_LENGTH, STYLE_NONE,
		(op_init_t)bsdsum_sha3_512_begin,
		(op_update_t)bsdsum_sha3_update,
		(op_final_t)bsdsum_sha3_final,
	},
	{
		"WHIRLPOOL", WHIRLPOOL_DIGEST_LEN, STYLE_NONE,
		(op_init_t)rhash_whirlpool_init,
		(op_update_t)rhash_whirlpool_update,
		(op_final_t)rhash_whirlpool_final,
	},
	{
		"BLAKE224", BLAKE224_DIGEST_LEN, STYLE_NONE,
		(op_init_t)blake224_init,
		(op_update_t)blake224_update,
		(op_final_t)blake224_final,
	},
	{
		"BLAKE256", BLAKE256_DIGEST_LEN, STYLE_NONE,
		(op_init_t)blake256_init,
		(op_update_t)blake256_update,
		(op_final_t)blake256_final,
	},
	{
		"BLAKE384", BLAKE384_DIGEST_LEN, STYLE_NONE,
		(op_init_t)blake384_init,
		(op_update_t)blake384_update,
		(op_final_t)blake384_final,
	},
	{
		"BLAKE512", BLAKE512_DIGEST_LEN, STYLE_NONE,
		(op_init_t)blake512_init,
		(op_update_t)blake512_update,
		(op_final_t)blake512_final,
	},
	{
		"BLAKE3", BLAKE3_OUT_LEN, STYLE_NONE,
		(op_init_t)blake3_hasher_init,
		(op_update_t)blake3_hasher_update,
		(op_final_t)blake3_final,
	},
	{
		"BLAKE2B", BLAKE2B_OUTBYTES, STYLE_NONE,
		(op_init_t)blake2b_start,
		(op_update_t)blake2b_update,
		(op_final_t)blake2b_end,
	},
	{
		"BLAKE2S", BLAKE2S_OUTBYTES, STYLE_NONE,
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
 * 'base64' may be 1 to ensure the algorithm that is found supports
 * base64 encoding.
 */
bsdsum_op_t* bsdsum_op_find_alg (const char *cp, int base64, int quiet)
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
			warnx( "bad algorithm name \"%s:%s\"", cp, p);
			return NULL;
		}
	}

	hf = bsdsum_op_get(cp);
	if (hf == NULL || hf->name == NULL) {
		if ( ! quiet)
			warnx("unknown algorithm \"%s\"", cp);
		return NULL;
	}
	if ((hf->style & STYLE_NOSPLIT) && l) {
		if ( ! quiet)
			warnx("algorithm \"%s\" does not support split", cp);
		return NULL;
	}
	if (hf->base64 == -1 && base64 != 0) {
		if ( ! quiet)
			warnx("%s doesn't support base64-style output", hf->name);
		return NULL;
	}
	hf->split = (int) l;
	return hf;
}

/* find the line format:
 * Possible forms:
 *  ALGORITHM (FILENAME) = CHECKSUM
 *  CHECKSUM  FILENAME
 *  CHECKSUM FILENAME
 * Returns STYLE_ or -1 on error.
 */
bsdsum_style_t bsdsum_op_parse (char *line, char **filename, char **dg,
				bsdsum_op_t **hf)
{
	char *p;
	char *q;
	size_t len;
	bsdsum_style_t st;
	int i;

	*hf = NULL;
	*filename = *dg = NULL;
	if (line == NULL)
		return STYLE_NONE;
	p = strchr(line, '\n');
	if (p)
		*p = '\0';
	if (*line == '\0')
		return STYLE_NONE;
	p = strchr(line, ' ');
	if (p == NULL)
		return STYLE_NONE;
	if (p[1] == '(') {
		*p++ = '\0';
		*p++ = '\0';
		*hf = bsdsum_op_find_alg(line, 0, 1);
		if (*hf == NULL)
			return STYLE_UNSUPPORTED;
		(*hf)->style = STYLE_NONE;
		(*hf)->base64 = 0;	
		*filename = p;
		p = strchr(p, ')');
		if (p == NULL)
			return STYLE_ERROR;
		*p++ = 0;
		if ((p[0] != ' ') || (p[1] != '=') || (p[2] != ' '))
			return STYLE_ERROR;
		*dg = p + 3;

		/* Check the length to see if this could be
		 * a valid checksum.  If hex, it will be 2x the
		 * size of the binary data.  For base64, we have
		 * to check both with and without the '=' padding. */
		len = strlen(*dg);
		if ((*hf)->use_style & STYLE_TEXT)
			(*hf)->style |= STYLE_TEXT;
		else if (len != (*hf)->digestlen * 2) {
			size_t len2;

			if ((*dg)[len - 1] == '=') {
				/* use padding */
				len2 = 4 * (((*hf)->digestlen + 2) / 3);
			} else {
				/* no padding */
				len2 = (4 * (*hf)->digestlen + 2) / 3;
			}
			if (len != len2)
				return STYLE_ERROR;
			(*hf)->base64 = 1;
			(*hf)->style |= STYLE_BASE64;
		}
		else {
			(*hf)->base64 = 0;
			(*hf)->style |= STYLE_DEFAULT;
		}
		return (*hf)->style;
	}

	/* GNU coreutils or cksum style */
	*dg = line;
	*p++ = '\0';
	if (*p == ' ') {
		st = STYLE_GNU;
		p++;			
	}
	else
		st = STYLE_CKSUM;
	*filename = p;
	len = strlen(*dg);
	for (i = 0; bsdsum_ops[i].name; i++) {
		if ( ! (bsdsum_ops[i].use_style & STYLE_SPACE))
			continue;
		if (len == bsdsum_ops[i].digestlen * 2)
			break;
	}
	if (bsdsum_ops[i].name == NULL)
		return STYLE_UNSUPPORTED;
	*hf = &bsdsum_ops[i];
	(*hf)->style = st;
	(*hf)->split = 0;
	(*hf)->base64 = 0;
	return st;
}


