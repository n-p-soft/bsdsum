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
	bs->ofile = -1;
}


/* copy 'hf' as tail of the list bs->hl and return it */
static bsdsum_op_t* bsdsum_add_op (bsdsum_t *bs, bsdsum_op_t *hf, 
					bsdsum_style_t st)
{
	bsdsum_op_t *hftmp;
	bsdsum_op_t *o;

	hftmp = calloc(1, sizeof(bsdsum_op_t));
	if (hftmp == NULL)
		err(1, "out of memory");
	memcpy(hftmp, hf, sizeof(bsdsum_op_t));
	hftmp->next = NULL;
	if (hf->use_style & STYLE_FIXED)
		hftmp->style = hf->use_style;
	else
		hftmp->style = st;
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

/* do the real stuff */
static void bsdsum_run(bsdsum_t* bs)
{
	int i;

	if (bs->selective_checklist) { /* -C */
		int i;

		bs->par = bsdsum_dgl_start(DGL_CMD_CHECK, -1,
						bs->selective_checklist);
		bs->par->sel_files = bs->argv;
		bs->par->sel_count = bs->argc;
		bs->par->sel_alg = bs->hl;
		bs->res = bsdsum_dgl_process(bs->par);
		bsdsum_dgl_end(&bs->par);
		if (bs->res & DGL_RES_ERROR)
			bs->error++;
	} 
	else if (bs->cflag) { /* -c */
		if (bs->argc == 0) {
			bs->par = bsdsum_dgl_start(DGL_CMD_CHECK, 0, NULL);
			bs->par->sel_alg = bs->hl;
			bs->res = bsdsum_dgl_process(bs->par);
			bsdsum_dgl_end(&bs->par);
			if (bs->res & DGL_RES_ERROR)
				bs->error++;
		}
		else {
			while (bs->argc--) {
				bs->par = bsdsum_dgl_start(DGL_CMD_CHECK, -1,
								*bs->argv++);
				bs->par->sel_alg = bs->hl;
				bs->res = bsdsum_dgl_process(bs->par);
				if (bs->res & DGL_RES_ERROR)
					bs->error++;
				bsdsum_dgl_end(&bs->par);
			}
		}
	} 
	else  if (bs->pflag || bs->argc == 0) /* -p or digest stdin */
		bs->error = bsdsum_digest_file(bs->ofile, bs->hl, "-", bs->pflag,
						-1, -1);
	else { /* digest files */
		for (i = 0; i < bs->argc; i++) 
			bs->error += bsdsum_digest_file(bs->ofile,
						bs->hl, bs->argv[i], 0,
						bs->offset, bs->length);
	}
}

/* check the configuration and adjust parameters */
static void bsdsum_setup(bsdsum_t* bs, int argc, char **argv)
{
	int fl;

	/* remaining arguments are files to digest or list of digests 
	 * to check. */
	bs->argc = argc;
	bs->argv = argv;

	/* Most arguments are mutually exclusive */
	if ((bs->argc != 1) && (bs->length >= 0 || bs->offset >= 0))
		errx(1, "one file (and only one) must be specified with -f/-l");
	fl = bs->pflag + bs->cflag;
	if (fl > 1 || (fl && bs->argc && bs->cflag == 0) || 
	    (bs->selective_checklist != NULL && bs->argc == 0))
		errx(1, "non-compatible options on command-line");
	if (bs->selective_checklist && bs->cflag)
		errx(1, "-C and -c are exclusive");
	if (bs->selective_checklist || bs->cflag) {
		if (bsdsum_count_op(bs) > 1)
			errx(1, "only one algorithm may be specified "
			    "in -C or -c mode");
	}

	/* default alg and style */
	if ((bsdsum_count_op(bs) == 0) && ! bs->cflag && 
		! bs->selective_checklist) {
		bsdsum_add_op(bs, bsdsum_op_get("SHA256"), bs->style);
	}

	/* split mode constrainsts */
	if (bs->use_split) {
		if (bs->pflag || bs->argc == 0)
			errx(1, "split digest not usable on stdin");
	}

	/* open -o path */
	if (bs->opath) {
		bs->ofile = open(bs->opath, O_WRONLY|O_CREAT|O_APPEND,
					0600);
		if (bs->ofile < 0)
			errx(1, "could not open %s", bs->opath);
	}
	else /* stdout */
		bs->ofile = 1;
}


/* parse command-line */
static void bsdsum_parse(bsdsum_t* bs, int argc, char** argv)
{
	bsdsum_op_t *hf, *hftmp;
	char *cp;
	const char *optstr = "a:C:co:hpts:f:l:";
	char* endptr;
	int i, fl;
	int a_opts = 0;

	/* Args pass 1 */
	while ((fl = getopt(argc, argv, optstr)) != -1) {
		switch (fl) {
		case 'h':
			bsdsum_help();
			exit(0);
			break;
		case 's':
			if (strcasecmp("base64", optarg) == 0) 
				bs->style = STYLE_B64;
			else if (strcasecmp("mix32", optarg) == 0) 
				bs->style = STYLE_M32;
			else if (strcasecmp("gnu", optarg) == 0)
				bs->style = STYLE_GNU;
			else if (strcasecmp("cksum", optarg) == 0)
				bs->style = STYLE_CKSUM;
			else if (strcasecmp("terse", optarg) == 0)
				bs->style = STYLE_TERSE;
			else if (strcasecmp("binary", optarg) == 0)
				bs->style = STYLE_BIN;
			else if (strcmp("default", optarg))
				errx(1, "unknown style: %s", optarg);
			break;
		case 'l':
			bs->length = strtol(optarg, &endptr, 0);
			if ((bs->length < 0) || (endptr && *endptr))
				errx(1, "bad value for -l");
			break;
		case 'f':
			bs->offset = strtol(optarg, &endptr, 0);
			if ((bs->offset < 0) || (endptr && *endptr))
				errx(1, "bad value for -f");
			break;
		case '?':
			bsdsum_help();
			exit(1);
		}
	}
	if (bs->length >= 0 || bs->offset >= 0) {
		if (bs->style == STYLE_NONE)
			bs->style = STYLE_TERSE;
		else if (bs->style != STYLE_TERSE)
			errx(1, "-f/-l implies -s terse");
	}
	if (bs->style == STYLE_NONE)
		bs->style = STYLE_HEXA;

	/* Args pass 2 */
	optind = 1;
	while ((fl = getopt(argc, argv, optstr)) != -1) {
		switch (fl) {
		case 'a':
			while ((cp = strsep(&optarg, ",")) != NULL) {
				if (*cp == '\0')
					continue;
				a_opts++;
				hf = bsdsum_op_find_alg(cp, bs->style, 0);
				if (hf == NULL) 
					errx(1, "unsupported algorithm and/or"
						       " style");
				hf = bsdsum_add_op(bs, hf, bs->style);
				if (hf->split >= 2)
					bs->use_split = 1;
			}
			break;
		case 'o':
			bs->opath = optarg;
			break;
		case 'C':
			bs->selective_checklist = optarg;
			break;
		case 'c':
			bs->cflag = 1;
			break;
		case 'p':
			bs->pflag = 1;
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

	bsdsum_setup(bs, argc - optind, argv + optind);	
}

static void bsdsum_end(bsdsum_t* bs)
{
	if (bs->opath)
		close(bs->ofile);
}

int main (int argc, char **argv)
{
	bsdsum_t bs;

	bsdsum_init(&bs);
	bsdsum_parse(&bs, argc, argv);
	bsdsum_run(&bs);
	bsdsum_end(&bs);

	return(bs.error ? EXIT_FAILURE : EXIT_SUCCESS);
}


