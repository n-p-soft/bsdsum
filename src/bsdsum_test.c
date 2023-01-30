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
	const char* name;
	const char* test;
	int test_len;
	const char* result; /* digest */
	const char* result2; /* filename */
	const char* result3; /* alg */
} tests[] = {
	/* digests tests */
	{ TEST_RESULT_STR, STYLE_TERSE, 
		"MD5", "abc", 3, "900150983cd24fb0d6963f7d28e17f72", },
	{ TEST_RESULT_STR, STYLE_TERSE, 
		"SHA1", "abc", 3, "a9993e364706816aba3e25717850c26c9cd0d89d", },
	{ TEST_RESULT_STR, STYLE_TERSE, 
		"SHA256", "abc", 3, "ba7816bf8f01cfea414140de5dae2223b00"
				"361a396177a9cb410ff61f20015ad", },
	{ TEST_RESULT_STR, STYLE_TERSE, 
		"SHA384", "0", 1, "5f91550edb03f0bb8917da57f0f8818976f5da971307b7"
		"ee4886bb951c4891a1f16f840dae8f655aa5df718884ebc15b", },
	{ TEST_RESULT_STR, STYLE_TERSE, 
		"SHA512", "abc", 3, "ddaf35a193617abacc417349ae20413112e6fa4e89a"
			"97ea20a9eeee64b55d39a2192992a274fc1a836ba3c"
			"23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", },
	{ TEST_RESULT_STR, STYLE_TERSE, 
		"SHA3-256", "", 0, "c5d2460186f7233c927e7db2dcc703c0e5"
			"00b653ca82273b7bfad8045d85a470", },
	{ TEST_RESULT_STR, STYLE_TERSE, 
		"SHA3-512", "", 0, "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7"
			"c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe"
			"06713b435f091ef2769fb160cdab33d3670680e", },
	{ TEST_RESULT_STR, STYLE_TXT,  "SIZE", "", 0, "0", },
	{ TEST_RESULT_STR, STYLE_TXT,  "SIZE", "abc", 3, "3", },
	{ TEST_RESULT_STR, STYLE_B64, 
		"MD5", "abc", 3, "kAFQmDzST7DWlj99KOF/cg==", },
	{ TEST_RESULT_STR, STYLE_TERSE, 
		"WHIRLPOOL", "", 0, 
		"19fa61d75522a4669b44e39c1d2e1726c530232130d407f89af"
		"ee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964"
		"e59b63d93708b138cc42a66eb3", },
	{ TEST_RESULT_STR, STYLE_TERSE, 
		"WHIRLPOOL", "a", 1,
		"8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c"
		"45001d0087b42d11bc645413aeff63a42391a39145a591a9220"
		"0d560195e53b478584fdae231a", },
	{ TEST_RESULT_STR, STYLE_TERSE,  "BLAKE224", 
		"\x00", 1,
		"4504cb0314fb2a4f7a692e696e487912fe3f2468fe312c73a5"
		"278ec5", },
	{ TEST_RESULT_STR, STYLE_TERSE,  "BLAKE256", 
		"\x00", 1,
    		"0ce8d4ef4dd7cd8d62dfded9d4edb0a7"
    		"74ae6a41929a74da23109e8f11139c87", },
	{ TEST_RESULT_STR, STYLE_TERSE,  "BLAKE384", 
		"\x00", 1,
    		"10281f67e135e90ae8e882251a355510"
    		"a719367ad70227b137343e1bc122015c"
    		"29391e8545b5272d13a7c2879da3d807", },
	{ TEST_RESULT_STR, STYLE_TERSE,  "BLAKE512", 
		"\x00", 1,
		"97961587f6d970faba6d2478045de6d1"
		"fabd09b61ae50932054d52bc29d31be4"
		"ff9102b9f69e2bbdb83be13d4b9c0609"
		"1e5fa0b48bd081b634058be0ec49beb3", },
	{ TEST_RESULT_STR, STYLE_TERSE,  "BLAKE3", 
		"", 0,
      		"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9"
		"a93cae41f3262",
	},
	{ TEST_RESULT_STR, STYLE_TERSE,  "BLAKE3", 
		"\x00", 1,
		"2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510"
		"225d0f592e213",
	},
	{ TEST_RESULT_STR, STYLE_TERSE,  "BLAKE3", 
		"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09" 
		"\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13" 
		"\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d" 
		"\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27" 
		"\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31" 
		"\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b" 
		"\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45" 
		"\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f" 
		"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59" 
		"\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63" 
		"\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d" 
		"\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77" 
		"\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81",
		129,
		"683aaae9f3c5ba37eaaf072aed0f9e30"
		"bac0865137bae68b1fde4ca2aebdcb12", 
	},
	{ TEST_RESULT_STR, STYLE_TERSE,  "BLAKE2S", 
		"", 0,
		"69217a3079908094e11121d042354a7c1f55b6482"
		"ca1a51e1b250dfd1ed0eef9",
	},
	{ TEST_RESULT_STR, STYLE_TERSE,  "BLAKE2S", 
		"abc", 3,
		"508c5e8c327c14e2e1a72ba34eeb452f37458b209"
		"ed63a294d999b4c86675982",
	},
	{ TEST_RESULT_STR, STYLE_TERSE,  "BLAKE2B", 
		"", 0,
		"786a02f742015903c6c6fd852552d272912f4740e"
		"15847618a86e217f71f5419d25e1031afee585313"
		"896444934eb04b903a685b1448b755d56f701afe9be2ce",
	},
	{ TEST_RESULT_STR, STYLE_TERSE,  "BLAKE2B", 
		"abc", 3,
		"ba80a53f981c4d0d6a2797b69f12f6e94c212f146"
		"85ac4b74b12bb6fdbffa2d17d87c5392aab792dc2"
		"52d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
	},
	/* parser tests */
	{ TEST_PARSE, STYLE_NONE,  
		"PARSE1", "", 0, NULL, NULL },
	{ TEST_PARSE, STYLE_UNSUPPORTED,  
		"PARSE2",  "XXX (file) = abcdef", -1, NULL, NULL },
	{ TEST_PARSE, STYLE_HEXA,  "PARSE3", 
		"MD5 (file) = 0123456789abcdef0123456789abcdef", -1,
		"0123456789abcdef0123456789abcdef", "file", "MD5" },
	{ TEST_PARSE, STYLE_ERROR,  "PARSE4", 
		"MD5 (file) = 123456789abcdef0123456789abcdef", -1,
		"123456789abcdef0123456789abcdef", "file", "MD5" },
	{ TEST_PARSE, STYLE_B64,  "PARSE5", 
		"MD5 (file) = kAFQmDzST7DWlj99KOF/cg==", -1,
		"kAFQmDzST7DWlj99KOF/cg==", "file", "MD5" },
	{ TEST_PARSE, STYLE_ERROR,  "PARSE6", 
		"MD5 (file) = !AFQmDzST7DWlj99KOF/cg==", -1,
		"!AFQmDzST7DWlj99KOF/cg==", "file", "MD5" },
	{ TEST_PARSE, STYLE_CKSUM,  "PARSE7",
		"0123456789abcdef0123456789abcdef cksum", -1,
		"0123456789abcdef0123456789abcdef", "cksum", "MD5" },
	{ TEST_PARSE, STYLE_GNU,  "PARSE8",
		"0123456789abcdef0123456789abcdef01234567  gnu", -1,
		"0123456789abcdef0123456789abcdef01234567", "gnu", "SHA1" },
	{ TEST_PARSE, STYLE_B64,  "PARSE9", 
		"MD5:2 (file) = kAFQmDzST7DWlj99KOF/cg==", -1,
		"kAFQmDzST7DWlj99KOF/cg==", "file", "MD5" },
	{ TEST_PARSE, STYLE_TXT,  "PARSE10", 
		"SIZE (file) = 123456", -1,
		"123456", "file", "SIZE" },
	{ 0, 0, NULL, NULL, 0, NULL, }
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
		fprintf(stderr, "* %s: OK\n", hf->name);
	else
		fprintf(stderr, "* %s: FAILED\n", hf->name);
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
static int bsdsum_test_md52() {
	const char *m2 = "5873dd45edd01f09c1ef2e7819369e8e";
	bsdsum_op_t *hf;
	unsigned char dummy = 0;

	hf = bsdsum_op_get("MD5");
	bsdsum_digest_init(hf, -1);
	hf->style = STYLE_TERSE;
	if (bsdsum_digest_mem(hf, &dummy, 0, 2))
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
	size_t len;
	
	fprintf (stderr, "starting bsdsum v" VERSION " auto-test\n");

	/* BLAKE tests */
	if (blake224_test() || blake256_test() ||
		blake384_test() || blake512_test()) {
		res = 1;
		fprintf (stderr, "* BLAKE reference tests: FAILED\n");
	}
	else
		fprintf (stderr, "* BLAKE reference tests: OK\n");

	/* our tests */
	for (i = 0; tests[i].test; i++) 
	{
		if (tests[i].type == TEST_RESULT_HEX ||
			tests[i].type == TEST_RESULT_STR) {
			hf = bsdsum_op_find_alg (tests[i].name, 
							tests[i].style, 1);
			bsdsum_digest_init(hf, -1);
			hf->style = tests[i].style;
			if (tests[i].test_len >= 0)
				len = tests[i].test_len;
			else
				len = strlen(tests[i].test);
			hf->update (hf->ctx,
					(const unsigned char*)tests[i].test, 
					len);
			bsdsum_digest_end(hf);
			if ( ! bsdsum_compare ((unsigned char*)hf->fdigest, 
						hf, &tests[i]))
				res = 1;
		} else if (tests[i].type == TEST_PARSE) {
			char* s;
			char* dg = NULL;
			char* filename = NULL;
			bsdsum_op_t *hf = NULL;
			bsdsum_style_t st;

			s = strdup(tests[i].test);
			st = bsdsum_dgl_parse_line(s, &filename, &dg, &hf);
			if ((st != tests[i].style) ||
				(hf && 
				! bsdsum_equ(hf->name, tests[i].result3)) ||
				! bsdsum_equ(filename, tests[i].result2) ||
				! bsdsum_equ(dg, tests[i].result)) {
				res = 1;	
				fprintf(stderr, "* %s: FAILED\n", tests[i].name);
				fprintf(stderr, "      <%s><%s><%s>\n", 
					dg, filename,
					hf ? hf->name : "-");
			}
			else
				fprintf(stderr, "* %s: OK\n", tests[i].name);
			free(s);
		}
	}
	if (bsdsum_test_md52()) {
		res = 1;
		fprintf(stderr, "* MD5_2: FAILED\n");
	}
	else
		fprintf(stderr, "* MD5_2: OK\n");

	exit (res);
}

