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
#include "sha3.h"

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
	sha3_ctx_t sha3;
	size_t size;
} bsdsum_ctx_t;

/* program global data */
typedef struct {
	int base64;
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

void size_init (bsdsum_ctx_t *ctx);

void size_update (bsdsum_ctx_t * ctx,
                  const unsigned char *data, size_t len);

void size_final (unsigned char *dg, bsdsum_ctx_t *ctx);

int b64_ntop(const u_char *src, size_t srclength, 
		char *target, size_t targsize);

void bsdsum_init(bsdsum_t *bs);

bsdsum_op_t* bsdsum_get_func(const char* name);

bsdsum_op_t* bsdsum_find_alg(const char *cp, int base64, int quiet);

int bsdsum_digest_run (bsdsum_op_t *hf,
			unsigned char* buf, long length, int split);

void bsdsum_digest_init(bsdsum_op_t *hf, int fd);

void bsdsum_digest_end(bsdsum_op_t *);

int  bsdsum_digest_file(bsdsum_t*, const char *, int);

void bsdsum_digest_print(FILE*, const bsdsum_op_t *, 
				const char *);

bsdsum_style_t bsdsum_parse(char *line, char **filename, char **dg,
				bsdsum_op_t **hf);

int bsdsum_digest_filelist(bsdsum_t*, const char *, bsdsum_op_t *, 
				int, char **);

void bsdsum_usage(void) __attribute__((__noreturn__));

void bsdsum_autotest(void);

#endif
