/*
 * Copyright (c) 2022-2023
 *      Nicolas Provost <dev@npsoft.fr>
 * Copyright (c) 2001,2003,2005-2007,2010,2013,2014
 *	Todd C. Miller <millert@openbsd.org>
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#ifndef __BSDSUM_H
#define __BSDSUM_H

#include <sys/types.h>
#include <stdio.h>
#include "sha/sha.h"
#include "md5/md5.h"
#include "bsdsum_sha3.h"
#include "whirlpool.h"
#include "blake.h"

/* output styles */
typedef enum {
	STYLE_NONE=0,
	STYLE_UNSUPPORTED=1,
	STYLE_ERROR=2,
	STYLE_DEFAULT,	/* ALG(FILE)=RESULT */
	STYLE_BASE64,	/* ALG(FILE)=BASE64_RESULT */
	STYLE_CKSUM,	/* RESULT FILE */
	STYLE_TERSE,	/* RESULT */
	STYLE_GNU,	/* RESULT  FILE */
	STYLE_BINARY,	/* raw binary */
	STYLE_MASK=0xf,
	STYLE_TEXT=0x100, /* flag for non-encoded output */	
	STYLE_NOSPLIT=0x200, /* alg does not support split */
	STYLE_SPACE=0x400, /* support GNU/cksum format "dg  file" */
} bsdsum_style_t;

/* buffer for storing binary digest */
#define MAX_DIGEST_LEN	128
typedef unsigned char bsdsum_digest_t[MAX_DIGEST_LEN+1];

/* buffer for storing formatted (hex, base64..) digest */
typedef char bsdsum_fdigest_t[2*MAX_DIGEST_LEN+1];

/* prototypes for one operator */
typedef void (*op_init_t)(void *);
typedef void (*op_update_t)(void *, const unsigned char *, size_t);
typedef void (*op_final_t)(unsigned char *, void *);

/* maximum count of threads for split-digest */
#define MAX_SPLIT 16

/* type of base64 encoding */
typedef enum {
	ENC64_NONE = 0,
	ENC64_DEFAULT = 1, /* default character set */
	ENC64_SYM = 2, /* use symbols */
} bsdsum_enc64_t;

/* descriptor for one operator */
typedef struct bsdsum_op {
	const char *name;
	size_t digestlen;
	bsdsum_style_t use_style; 
	void (*init)(void *);
	void (*update)(void *, const unsigned char *, size_t);
	void (*final)(unsigned char *, void *);
	void *ctx;
	int style;
	int base64;
	bsdsum_enc64_t enc64; /* character set when using base64 */
	int split; /* N for algorithm ALG:N, 2 <= N <= 16 */
	bsdsum_digest_t digest; /* output buffer (binary) */
	bsdsum_fdigest_t fdigest; /* output buffer (formatted) */
	int digest_fd; /* if >= 0, write the binary digest into this file */
	struct bsdsum_op *next;
} bsdsum_op_t;

/* unified operator context */
typedef union bsdsum_ctx {
	MD5_CTX md5;
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;
	bsdsum_sha3_ctx_t sha3;
	whirlpool_ctx whirlpool;
	size_t size;
	blake224_ctx blake224;
	blake256_ctx blake256;
	blake384_ctx blake384;
	blake512_ctx blake512;
} bsdsum_ctx_t;

/* program global data */
typedef struct {
	int base64;
	bsdsum_enc64_t enc64;
	int cflag;
	int pflag;
	bsdsum_style_t style;
	long length;
	long offset;
	int ofile;
	bsdsum_op_t *hl;
	int error;
	char *selective_checklist;
	unsigned char *data;
	const char *current_file;
} bsdsum_t;

/* length of 'data' field above */
#define BUFFER_SZK 32

void explicit_bzero(void* p, size_t sz);

void bsdsum_size_init (bsdsum_ctx_t *ctx);

void bsdsum_size_update (bsdsum_ctx_t * ctx,
     		             const unsigned char *data, size_t len);

void bsdsum_size_final (unsigned char *dg, bsdsum_ctx_t *ctx);

int bsdsum_b64_ntop(const unsigned char *src, size_t srclength, 
			char *target, size_t targsize,
			bsdsum_enc64_t enc);

bsdsum_op_t* bsdsum_op_get(const char* name);

bsdsum_op_t* bsdsum_op_find_alg(const char *cp, int base64, int quiet);

bsdsum_style_t bsdsum_op_parse(char *line, char **filename, char **dg,
				bsdsum_op_t **hf);

int bsdsum_digest_run (bsdsum_op_t *hf,
			unsigned char* buf, long length, int split);

void bsdsum_digest_init(bsdsum_op_t *hf, int fd);

void bsdsum_digest_end(bsdsum_op_t *);

int  bsdsum_digest_file(bsdsum_t*, const char *, int);

void bsdsum_digest_print(int, const bsdsum_op_t *, 
				const char *);

int bsdsum_digest_filelist(bsdsum_t*, const char *, bsdsum_op_t *, 
				int, char **);

void bsdsum_help(void);

void bsdsum_autotest(void);

char* bsdsum_getline(int fd, int* eof, const char *filename);

#endif
