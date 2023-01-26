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
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include "bsdsum.h"

/*****************************************************************************
 * BSDSUM MINI TEST SUITE                                                    *
 *****************************************************************************/
typedef enum {
	TEST_RESULT_STR = 0,
	TEST_RESULT_HEX = 1,
	TEST_PARSE = 2,
} bsdsum_test_type_t;

struct bsdsum_test {
	bsdsum_test_type_t type;	
	bsdsum_style_t style;
	bsdsum_enc64_t enc64;
	const char* name;
	const char* test;
	const char* result; /* digest */
	const char* result2; /* filename */
	const char* result3; /* alg */
} tests[] = {
	/* digests tests */
	{ TEST_RESULT_STR, STYLE_DEFAULT, ENC64_NONE,
		"MD5", "abc", "900150983cd24fb0d6963f7d28e17f72", },
	{ TEST_RESULT_STR, STYLE_DEFAULT, ENC64_NONE,
		"SHA1", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d", },
	{ TEST_RESULT_STR, STYLE_DEFAULT, ENC64_NONE,
		"SHA256", "abc", "ba7816bf8f01cfea414140de5dae2223b00"
				"361a396177a9cb410ff61f20015ad", },
	{ TEST_RESULT_STR, STYLE_DEFAULT, ENC64_NONE,
		"SHA384", "0", "5f91550edb03f0bb8917da57f0f8818976f5da971307b7"
		"ee4886bb951c4891a1f16f840dae8f655aa5df718884ebc15b", },
	{ TEST_RESULT_STR, STYLE_DEFAULT, ENC64_NONE,
		"SHA512", "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a"
			"97ea20a9eeee64b55d39a2192992a274fc1a836ba3c"
			"23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", },
	{ TEST_RESULT_STR, STYLE_TERSE, ENC64_NONE,
		"SHA3-256", "", "c5d2460186f7233c927e7db2dcc703c0e5"
			"00b653ca82273b7bfad8045d85a470", },
	{ TEST_RESULT_STR, STYLE_TERSE, ENC64_NONE,
		"SHA3-512", "", "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7"
			"c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe"
			"06713b435f091ef2769fb160cdab33d3670680e", },
	{ TEST_RESULT_STR, STYLE_TERSE, ENC64_NONE, "SIZE", "", "0", },
	{ TEST_RESULT_STR, STYLE_TERSE, ENC64_NONE, "SIZE", "abc", "3", },
	{ TEST_RESULT_STR, STYLE_BASE64, ENC64_DEFAULT,
		"MD5", "abc", "kAFQmDzST7DWlj99KOF/cg==", },
	{ TEST_RESULT_STR, STYLE_TERSE, ENC64_NONE,
		"WHIRLPOOL", "", 
		"19fa61d75522a4669b44e39c1d2e1726c530232130d407f89af"
		"ee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964"
		"e59b63d93708b138cc42a66eb3", },
	{ TEST_RESULT_STR, STYLE_TERSE, ENC64_NONE,
		"WHIRLPOOL", "abc", 
		"8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c"
		"45001d0087b42d11bc645413aeff63a42391a39145a591a9220"
		"0d560195e53b478584fdae231a", },
	/* parser tests */
	{ TEST_PARSE, STYLE_NONE, ENC64_NONE, 
		"PARSE1", "", NULL, NULL },
	{ TEST_PARSE, STYLE_UNSUPPORTED, ENC64_NONE, 
		"PARSE2", 
		"XXX (file) = abcdef", NULL, NULL },
	{ TEST_PARSE, STYLE_DEFAULT, ENC64_NONE, "PARSE3", 
		"MD5 (file) = 0123456789abcdef0123456789abcdef", 
		"0123456789abcdef0123456789abcdef", "file", "MD5" },
	{ TEST_PARSE, STYLE_ERROR, ENC64_NONE, "PARSE4", 
		"MD5 (file) = 123456789abcdef0123456789abcdef", 
		"123456789abcdef0123456789abcdef", "file", "MD5" },
	{ TEST_PARSE, STYLE_BASE64, ENC64_NONE, "PARSE5", 
		"MD5 (file) = kAFQmDzST7DWlj99KOF/cg==",
		"kAFQmDzST7DWlj99KOF/cg==", "file", "MD5" },
	{ TEST_PARSE, STYLE_CKSUM, ENC64_NONE, "PARSE6",
		"0123456789abcdef0123456789abcdef cksum",
		"0123456789abcdef0123456789abcdef", "cksum", "MD5" },
	{ TEST_PARSE, STYLE_GNU, ENC64_NONE, "PARSE7",
		"0123456789abcdef0123456789abcdef01234567  gnu",
		"0123456789abcdef0123456789abcdef01234567", "gnu", "SHA1" },
	{ TEST_PARSE, STYLE_BASE64, ENC64_NONE, "PARSE8", 
		"MD5:2 (file) = kAFQmDzST7DWlj99KOF/cg==",
		"kAFQmDzST7DWlj99KOF/cg==", "file", "MD5" },
	{ TEST_PARSE, STYLE_TEXT, ENC64_NONE, "PARSE9", 
		"SIZE (file) = 123456",
		"123456", "file", "SIZE" },
	{ 0, 0, 0, NULL, }
};

static unsigned char bsdsum_hexdg (char c)
{
	if ((c >= '0') && (c <= '9'))
		return (unsigned char)c - '0';
	else if ((c >= 'a') && (c <= 'f'))
		return (unsigned char)c - 'a' + 10;
	else if ((c >= 'A') && (c <= 'F'))
		return (unsigned char)c - 'A' + 10;
	else
		errx(1, "bad hex value");
}

static bool bsdsum_compare (unsigned char *dg, bsdsum_op_t *hf,
				const struct bsdsum_test *test)
{
	int i;
	unsigned char c;
	bool res = true;

	if (test->type == TEST_RESULT_STR)
		res = (strcmp ((const char*) dg, test->result) == 0);
	else if (test->type == TEST_RESULT_HEX)
	{
		if (strlen (test->result) != 2*hf->digestlen)
			res = false;
		for (i = 0; res && (i < hf->digestlen); i++)
		{
			c = (bsdsum_hexdg (test->result[2*i]) << 4) + 
				bsdsum_hexdg (test->result[2*i+1]);
			if (c != dg[i])
				res = false;
		}
	}
	if (res)
		fprintf(stderr, "%s: OK\n", hf->name);
	else
		fprintf(stderr, "%s: FAILED\n", hf->name);

	return res;
}

static int bsdsum_equ(const char* a, const char* b)
{
	if (a) {
		if (b)
			return (strcmp(a, b) == 0);
		else
			return 0;
	} 
	else
		return (a == b);
}

/* check that MD5:2=MD5(MD5(part1)|MD5(part2)) for size 0: 
 * MD5(part)=d41d8cd98f00b204e9800998ecf8427e */
static int bsdsum_md52test() {
	const char *m2 = "5873dd45edd01f09c1ef2e7819369e8e";
	bsdsum_op_t *hf;
	unsigned char dummy = 0;

	hf = bsdsum_op_get("MD5");
	bsdsum_digest_init(hf, -1);
	hf->style = STYLE_TERSE;
	hf->base64 = 0;
	if (bsdsum_digest_run(hf, &dummy, 0, 2))
		return 1;
	if (strcmp (hf->fdigest, m2))
		return 1;

	return 0;
};

void bsdsum_autotest(void)
{
	bsdsum_op_t *hf;
	int res = 0;
	int i;
	
	fprintf (stderr, "starting bsdsum v" VERSION " auto-test\n");
	for (i = 0; tests[i].test; i++) 
	{
		if (tests[i].type == TEST_RESULT_HEX ||
			tests[i].type == TEST_RESULT_STR) {
			hf = bsdsum_op_find_alg (tests[i].name, 0, 1);
			bsdsum_digest_init(hf, -1);
			hf->style = tests[i].style | hf->use_style;
			hf->base64 = (tests[i].style == STYLE_BASE64);
			if (hf->base64)
				hf->enc64 = tests[i].enc64;
			hf->update (hf->ctx, (const unsigned char*)tests[i].test, 
					strlen(tests[i].test));
			bsdsum_digest_end(hf);
			if ( ! bsdsum_compare ((unsigned char*)hf->fdigest, hf, &tests[i]))
				res = 1;
		} else if (tests[i].type == TEST_PARSE) {
			char* s;
			char* dg = NULL;
			char* filename = NULL;
			bsdsum_op_t *hf = NULL;
			bsdsum_style_t st;

			s = strdup(tests[i].test);
			st = bsdsum_op_parse(s, &filename, &dg, &hf);
			if ((st != tests[i].style) ||
				(hf && 
				! bsdsum_equ(hf->name, tests[i].result3)) ||
				! bsdsum_equ(filename, tests[i].result2) ||
				! bsdsum_equ(dg, tests[i].result)) {
				res = 1;	
				fprintf(stderr, "%s: FAILED\n", tests[i].name);
				fprintf(stderr, "  <%s><%s><%s>\n", 
					dg, filename,
					hf ? hf->name : "-");
			}
			else
				fprintf(stderr, "%s: OK\n", tests[i].name);
			free(s);
		}
	}
	if (bsdsum_md52test()) {
		res = 1;
		fprintf(stderr, "MD5_2: FAILED\n");
	}
	else
		fprintf(stderr, "MD5_2: OK\n");

	exit (res);
}

