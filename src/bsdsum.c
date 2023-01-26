/*
 * Copyright (c) 2022-2023
 *      Nicolas Provost <dev AT npsoft DOT fr>
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

static void bsdsum_init (bsdsum_t *bs)
{
	memset(bs, 0, sizeof(bsdsum_t));
	bs->length = -1;
	bs->offset = -1;
	bs->style = STYLE_DEFAULT;
	bs->data = calloc(BUFFER_SZK, 1024);
	bs->ofile = -1;
	bs->enc64 = ENC64_NONE;
}


/* copy 'hf' as tail of the list bs->hl and return it */
static bsdsum_op_t* bsdsum_add_op (bsdsum_t *bs, bsdsum_op_t *hf, 
					bsdsum_enc64_t enc64)
{
	bsdsum_op_t *hftmp;
	bsdsum_op_t *o;

	hftmp = calloc(1, sizeof(*hftmp));
	if (hftmp == NULL)
		err(1, "out of memory");
	*hftmp = *hf;
	if (enc64 != ENC64_NONE) {
		hftmp->base64 = 1;
		hftmp->enc64 = enc64;
	}
	hftmp->next = NULL;
	if (bs->hl == NULL)
		bs->hl = hftmp;
	else {
		for (o = bs->hl; o && o->next; o = o->next) { }
		o->next = hftmp;
	}
	return hftmp;
}

/* count the number of operations in bs->hl */
static int bsdsum_count_op (bsdsum_t *bs)
{
	bsdsum_op_t *o;
	int n;

	for (n = 0, o = bs->hl; o; o = o->next, n++) { }
	return n;
}

int main (int argc, char **argv)
{
	bsdsum_t bs;
	bsdsum_op_t *hf, *hftmp;
	char *cp;
	const char *optstr = "a:C:co:hpts:f:l:";
	char* endptr;
	int fl, i;
	int use_split = 0;
	int style_spec = 0;
	int a_opts = 0;

	bsdsum_init(&bs);

	/* Args pass 1 */
	while ((fl = getopt(argc, argv, optstr)) != -1) {
		switch (fl) {
		case 'h':
			bsdsum_help();
			exit(0);
			break;
		case 's':
			if (strcasecmp("base64", optarg) == 0) {
				bs.style = STYLE_BASE64;
				bs.enc64 = ENC64_DEFAULT;
			}
			else if (strcasecmp("sym64", optarg) == 0) {
				bs.style = STYLE_BASE64;
				bs.enc64 = ENC64_SYM;
			}
			else if (strcasecmp("gnu", optarg) == 0)
				bs.style = STYLE_GNU;
			else if (strcasecmp("cksum", optarg) == 0)
				bs.style = STYLE_CKSUM;
			else if (strcasecmp("terse", optarg) == 0)
				bs.style = STYLE_TERSE;
			else if (strcasecmp("binary", optarg) == 0)
				bs.style = STYLE_BINARY;
			else if (strcasecmp("default", optarg)) {
				bsdsum_help();
				exit(1);
			}
			style_spec = 1;
			break;
		case 'l':
			bs.length = strtol(optarg, &endptr, 0);
			if ((bs.length < 0) || (endptr && *endptr))
				errx(1, "bad value for -l");
			break;
		case 'f':
			bs.offset = strtol(optarg, &endptr, 0);
			if ((bs.offset < 0) || (endptr && *endptr))
				errx(1, "bad value for -f");
			break;
		case '?':
			bsdsum_help();
			exit(1);
		}
	}
	if (bs.length >= 0 || bs.offset >= 0) {
		if (style_spec && bs.style != STYLE_TERSE)
			errx(1, "-f/-l implies -s terse");
		bs.style = STYLE_TERSE;
		bs.base64 = 0;
	}

	/* Args pass 2 */
	optind = 1;
	bs.base64 = (bs.style == STYLE_BASE64) ? 1 : 0;
	while ((fl = getopt(argc, argv, optstr)) != -1) {
		switch (fl) {
		case 'a':
			while ((cp = strsep(&optarg, ",")) != NULL) {
				if (*cp == '\0')
					continue;
				a_opts++;
				hf = bsdsum_op_find_alg(cp, bs.base64, 0);
				if (hf == NULL) 
					errx(1, "unsupported algorithm");
				if ((bs.style == STYLE_GNU ||
					bs.style == STYLE_CKSUM) &&
					( ! (hf->style & STYLE_SPACE) ||
					(hf->split >= 2)))
					errx(1, "style not supported for %s",
						cp);
				hf = bsdsum_add_op(&bs, hf, bs.enc64);
				if (hf->split >= 2)
					use_split = 1;
				hf->style = bs.style | hf->use_style;
			}
			break;
		case 'o':
			bs.ofile = open(optarg, O_WRONLY|O_CREAT|O_APPEND,
					0600);
			if (bs.ofile < 0)
				errx(1, "could not open %s", optarg);
			break;
		case 'C':
			bs.selective_checklist = optarg;
			break;
		case 'c':
			bs.cflag = 1;
			break;
		case 'p':
			bs.pflag = 1;
			break;
		case 't':
			bsdsum_autotest();
			break;
		case 'f':
		case 'l':
		case 's':
			/* already processed */
			break;
		default:
			bsdsum_help();
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (bs.ofile < 0)
		bs.ofile = 1;

	/* Most arguments are mutually exclusive */
	if ((argc != 1) && (bs.length >= 0 || bs.offset >= 0))
		errx(1, "one file (and only one) must be specified with -f/-l");
	fl = bs.pflag + bs.cflag;
	if (fl > 1 || (fl && argc && bs.cflag == 0) || 
	    (bs.selective_checklist != NULL && argc == 0))
		errx(1, "non-compatible options on command-line");
	if (bs.selective_checklist || bs.cflag) {
		if (a_opts > 1)
			errx(1, "only one algorithm may be specified "
			    "in -C or -c mode");
	}

	/* missing alg name */
	if ((bsdsum_count_op(&bs) == 0) && ! bs.cflag && 
		! bs.selective_checklist) 
		errx(1, "missing algorithm name (-a)");

	/* split mode constrainsts */
	if (use_split) {
		if (bs.pflag || argc == 0)
			errx(1, "split digest not usable on stdin");
	}
	
	/* -c/-C */
	if (bs.selective_checklist) {
		int i;

		bs.error = bsdsum_digest_filelist(&bs, bs.selective_checklist, 
							bs.hl, argc, argv);
		for (i = 0; i < argc; i++) {
			if (argv[i] != NULL) {
				warnx("%s does not exist in %s", argv[i],
				    bs.selective_checklist);
				bs.error++;
			}
		}
	} 
	else if (bs.cflag) {
		if (argc == 0)
			bs.error = bsdsum_digest_filelist(&bs, "-", bs.hl,
								0, NULL);
		else {
			while (argc--) {
				bs.error += bsdsum_digest_filelist(&bs, *argv++,
			  					bs.hl, 0, NULL);
			}
		}
	} 
	else {
		if (bs.pflag || argc == 0)
			bs.error = bsdsum_digest_file(&bs, "-", bs.pflag);
		else {
			for (i = 0; i < argc; i++) 
				bs.error += bsdsum_digest_file(&bs, argv[i], 0);
		}
	}

	close(bs.ofile);
	return(bs.error ? EXIT_FAILURE : EXIT_SUCCESS);
}


