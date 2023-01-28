/*
 * Copyright (c) 2022-2023
 *      Nicolas Provost <dev@npsoft.fr>
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

#ifndef __BSDSUM_H
#define __BSDSUM_H

#include <sys/types.h>
#include <stdio.h>
#include "sha/sha.h"
#include "md5/md5.h"
#include "bsdsum_sha3.h"
#include "whirlpool.h"
#include "blake.h"
#include "blake2.h"
#include "blake3.h"

/* output styles */
typedef enum {
	STYLE_NONE=0,
	STYLE_UNSUPPORTED=1,
	STYLE_ERROR=2,
	STYLE_COMMENT, 	/* comment line in list of digests */
	/* flags for output style */
	STYLE_HEXA=0x100,	/* ALG(FILE)=HEX_RESULT*/
	STYLE_B64=0x200,	/* ALG(FILE)=BASE64_RESULT */
	STYLE_M32=0x400,	/* ALG(FILE)=MIX32_RESULT */
	STYLE_CKSUM=0x800,	/* RESULT_HEXA FILE */
	STYLE_TERSE=0x1000,	/* RESULT */
	STYLE_GNU=0x2000,	/* RESULT_HEXA  FILE */
	STYLE_BIN=0x4000,	/* raw binary */
	STYLE_TXT=0x8000, 	/* ALG(FILE)=RAW_DIGEST */	
	STYLE_NOSPLIT=0x10000, 	/* alg does not support split */
	STYLE_ANY=STYLE_HEXA+STYLE_B64+STYLE_M32+STYLE_CKSUM+
			STYLE_GNU+STYLE_TERSE+STYLE_BIN,
	STYLE_BSD=STYLE_HEXA+STYLE_B64+STYLE_M32+
			STYLE_TERSE+STYLE_BIN,
	STYLE_CASE_MATCH=0x20000, /* digest comparison case matters */
	STYLE_FIXED=0x40000, /* style cannot be changed for this alg */
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

/* type of base32 encoding */
typedef enum {
	SET32_NONE = 0,
	SET32_MIX = 1, /* default mixed character set */
} bsdsum_set32_t;

/* descriptor for one operator */
typedef struct bsdsum_op {
	const char *name;
	const size_t digestlen;
	const bsdsum_style_t use_style; 
	void (*init)(void *);
	void (*update)(void *, const unsigned char *, size_t);
	void (*final)(unsigned char *, void *);
	void *ctx;
	bsdsum_style_t style;
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
	blake3_hasher blake3;
	blake2b_state blake2b;
	blake2s_state blake2s;
} bsdsum_ctx_t;

/* Operation to run on a list of digests */
typedef enum {
	DGL_CMD_NONE = 0,
	DGL_CMD_CHECK, /* verify the digests */
} bsdsum_dgl_cmd_t;

/* Result codes for dgl_process */
typedef enum {
	DGL_RES_OK = 0,
	DGL_RES_ERR_PAR, /* bad input parameters */
	DGL_RES_ERR_IO, /* IO error while reading the list */
	/* flags */
	DGL_RES_CONTINUE = 0x1000, /* continue the list processing */
	DGL_RES_BREAK = 0x2000, /* stop list processing */
	DGL_RES_ERROR = 0x4000, /* at least one error */
} bsdsum_dgl_res_t;

/* Parameters for dgl_process function: */
typedef struct {
	const char *path; /* path of the list */
	int listfd; /* file descriptor of the list */
	int std; /* 1 if using stdin (path is "-") */
	bsdsum_dgl_cmd_t cmd; /* op to run on the list of digests */
	int l_comment; /* count of commented-out lines */
	int l_skipped; /* count of lines skipped during operation */
	int l_syntax; /* count of ill-formatted lines (no op applied) */
	int l_error; /* count of lines with operation failure */
	int l_empty; /* count of empty lines */
	int l_ok; /* count of lines processed OK */
	int lineno; /* current line number */

	/* parameters for CHECK */
	bsdsum_op_t* sel_alg; /* alg selected when checking or NULL */
	char **sel_files; /* only check these files if not NULL */
	int sel_count; /* count of items in sel_files */
	int *sel_found; /* 1 for each item of sel_files found */
} bsdsum_dgl_par_t;

/* program global data */
typedef struct {
	int argc;
	char **argv;
	int use_split;
	int cflag;
	int pflag;
	bsdsum_style_t style;
	long length;
	long offset;
	const char *opath; /* -o path */
	int ofile; /* -o associated file descriptor */
	bsdsum_op_t *hl;
	char *selective_checklist;
	bsdsum_dgl_par_t *par;
	bsdsum_dgl_res_t res;
	int error;
} bsdsum_t;

/* length of 'data' field above */
#define BUFFER_SZK 32

void explicit_bzero(void* p, size_t sz);

void bsdsum_size_init (bsdsum_ctx_t *ctx);

void bsdsum_size_update (bsdsum_ctx_t * ctx,
     		             const unsigned char *data, size_t len);

void bsdsum_size_final (unsigned char *dg, bsdsum_ctx_t *ctx);

int bsdsum_b64_ntop(const unsigned char *src, size_t srclength, 
			char *target, size_t targsize);

bool bsdsum_b64_test (const char *s, size_t dlen);

bsdsum_op_t* bsdsum_op_get(const char* name);

bsdsum_op_t* bsdsum_op_find_alg(const char *cp, 
				bsdsum_style_t style, int quiet);

bsdsum_op_t* bsdsum_op_for_length(size_t len);

bool bsdsum_op_case_sensitive(bsdsum_style_t st);

int bsdsum_digest_run (bsdsum_op_t *hf,
			unsigned char* buf, long length, int split);

int bsdsum_digest_mmap_file (const char *file,
				bsdsum_op_t *hf,
				long offset, long length);

void bsdsum_digest_init(bsdsum_op_t *hf, int fd);

void bsdsum_digest_end(bsdsum_op_t *);

int  bsdsum_digest_file(int ofile, bsdsum_op_t* ops, 
			const char *file, int echo,
			long offset, long length);

void bsdsum_digest_print(int, const bsdsum_op_t *, 
				const char *);

bsdsum_dgl_par_t* bsdsum_dgl_start(bsdsum_dgl_cmd_t cmd,
					int listfd, const char *path);

void bsdsum_dgl_end(bsdsum_dgl_par_t**);

bsdsum_dgl_res_t bsdsum_dgl_process(bsdsum_dgl_par_t *par);

bsdsum_style_t bsdsum_dgl_parse_line (char *line, 
					char **filename, char **dg,
					bsdsum_op_t **hf);

void bsdsum_help(void);

void bsdsum_autotest(void);

char* bsdsum_getline(int fd, int* eof, const char *filename);

char* bsdsum_enc_32 (const unsigned char *data, size_t len,
			bsdsum_set32_t set, size_t *olen);

bsdsum_style_t bsdsum_enc_test(const char *s, size_t alg_len);

#endif
