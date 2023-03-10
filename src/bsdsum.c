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
	bs->log_lvl = LL_DEF;
	bs->log_fd = -1;
}


/* copy 'hf' as tail of the list bs->hl and return it */
static bsdsum_op_t* bsdsum_add_op (bsdsum_t *bs, bsdsum_op_t *hf, 
					bsdsum_style_t st)
{
	bsdsum_op_t *hftmp;
	bsdsum_op_t *o;

	hftmp = calloc(1, sizeof(bsdsum_op_t));
	if (hftmp == NULL)
		bsdsum_log(LL_ERR|LL_FATAL, "out of memory");
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
	if (bs->selective_checklist) { /* -C */
		bs->par = bsdsum_dgl_start(DGL_CMD_CHECK_SEL, 
						bs->flags, -1,
						bs->selective_checklist);
		bs->par->prepend = bs->prepend;
		bs->par->files = bs->argv;
		bs->par->files_count = bs->argc;
		bs->par->algs = bs->hl;
	} 
	else if (bs->flags & FLAG_C) { /* -c */
		bs->par = bsdsum_dgl_start(DGL_CMD_CHECK_LISTS, 
					bs->flags,
					(bs->argc == 0) ? 0 : -1, 
					NULL);
		bs->par->algs = bs->hl;
		bs->par->prepend = bs->prepend;
		bs->par->files = (bs->argc == 0) ?  NULL : bs->argv;
		bs->par->files_count = bs->argc;
	} 
	else  if ((bs->flags & FLAG_P) || bs->argc == 0) { 
		/* -p or digest stdin */
		bs->par = bsdsum_dgl_start(DGL_CMD_HASH_STDIN, 
					bs->flags,
					bs->opath ? -1 : 1, bs->opath);
		bs->par->algs = bs->hl;
		bs->par->prepend = bs->prepend;
	}
	else { 
		/* digest files */
		bs->par = bsdsum_dgl_start(DGL_CMD_HASH, bs->flags,
					bs->opath ? -1 : 1, bs->opath);
		bs->par->files = bs->argv;
		bs->par->files_count = bs->argc;
		bs->par->algs = bs->hl;
		bs->par->offset = bs->offset;
		bs->par->length = bs->length;
		bs->par->prepend = bs->prepend;
	}
	bs->res = bsdsum_dgl_process(bs->par);
	bsdsum_dgl_end(&bs->par);
	if (bs->res & RES_ERROR)
		bs->error++;
}

/* check the configuration and adjust parameters */
static void bsdsum_setup(bsdsum_t* bs, int argc, char **argv)
{
	int fl = 0;
	struct stat st;

	/* remaining arguments are files to digest or list of digests 
	 * to check. */
	bs->argc = argc;
	bs->argv = argv;

	/* check command-line options */
	if ((bs->length >= 0 || bs->offset >= 0)) {
		if (bs->argc != 1)
			bsdsum_log(LL_ERR|LL_FATAL, 
					"one file (and only one) must be "
					"specified with -f/-l");
		if (bs->flags & (FLAG_P | FLAG_K | FLAG_C | FLAG_CSEL |
					FLAG_R))
			bsdsum_log(LL_ERR|LL_FATAL, 
				"non-compatible options on command-line");
	}
	if (bs->selective_checklist != NULL && bs->argc == 0)
		bsdsum_log(LL_ERR|LL_FATAL, 
			"missing selection of files to check");
	if ((bs->flags & FLAG_C) && bs->argc == 0)
		bsdsum_log(LL_ERR|LL_FATAL, 
			"missing list(s) of digests to check");
	if ((bs->flags & FLAG_R) && 
		(bs->flags & (FLAG_C | FLAG_CSEL | FLAG_P)))
		bsdsum_log(LL_ERR|LL_FATAL, 
			"non-compatible option -r on command-line");
	if (bs->flags & FLAG_C)
		fl++;
	if (bs->flags & FLAG_P)
		fl++;
	if (bs->flags & FLAG_CSEL)
		fl++;
	if (fl > 1) 
		bsdsum_log(LL_ERR|LL_FATAL, 
				"-p, -C and -c are exclusive");
	if (fl && (bs->flags & (FLAG_K | FLAG_R)))
		bsdsum_log(LL_ERR|LL_FATAL, 
			"non-compatible options on command-line");
	if (bs->selective_checklist || (bs->flags & FLAG_C)) {
		if (bsdsum_count_op(bs) > 1)
			bsdsum_log(LL_ERR|LL_FATAL, 
				"only one algorithm may be specified "
				"in -C or -c mode");
	}

	/* default alg and style */
	if ((bsdsum_count_op(bs) == 0) && ! (bs->flags & FLAG_C) && 
		! bs->selective_checklist) {
		bsdsum_add_op(bs, bsdsum_op_get("SHA256"), bs->style);
	}

	/* split mode constrainsts */
	if (bs->flags & FLAG_SPLIT) {
		if ((bs->flags & FLAG_P) || bs->argc == 0)
			bsdsum_log(LL_ERR|LL_FATAL, 
				"split digest not usable on stdin");
	}

	/* prepend path checking */
	if (bs->prepend) {
		char *s;
		size_t len = strlen(bs->prepend);

		if ((len == 0) || stat(bs->prepend, &st)) {
			bsdsum_log(LL_ERR|LL_FATAL,
				"path to prepend (%s) is not valid");
		}
		if ((st.st_mode & S_IFMT) != S_IFDIR) {
			bsdsum_log(LL_ERR|LL_FATAL,
			"path to prepend (%s) is not a directory");
		}
		if (bs->prepend[len-1] != '/') {
			s = calloc(len+2, 1);
			if (s)
				snprintf(s, len+2, "%s/", bs->prepend);
		}
		else
			s = strdup(bs->prepend);
		if (s == NULL)
			bsdsum_log(LL_ERR|LL_FATAL, "out of memory");
		bs->prepend = s;
	}
}


/* parse command-line */
static void bsdsum_parse(bsdsum_t* bs, int argc, char** argv)
{
	bsdsum_op_t *hf, *hftmp;
	char *cp;
	const char *optstr = "a:C:co:d:v:hprkts:f:l:";
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
		case 'v':
			if (strcasecmp("default", optarg) == 0)
				bs->log_lvl = LL_DEF;
			else if (strcasecmp("verbose", optarg) == 0)
				bs->log_lvl = LL_DEF|LL_VERBOSE;
			else if (strcasecmp("debug", optarg) == 0)
				bs->log_lvl = LL_DEF|LL_VERBOSE|
						LL_DEBUG;
			else if (strcasecmp("errors", optarg) == 0)
				bs->log_lvl &= ~ LL_WARN;
			else if (strcasecmp("nothing", optarg) == 0)
				bs->log_lvl = LL_NONE;
			else if (strncmp("file=", optarg, 5) == 0) 
				bs->log = optarg + 5;
			else
				bsdsum_log(LL_ERR|LL_FATAL, 
					"unknown message filter: %s", 
					optarg);
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
			else if (strcasecmp("default", optarg) == 0)
				bs->style = STYLE_HEXA;
			else
				bsdsum_log(LL_ERR|LL_FATAL, 
					"unknown style: %s", optarg);
			break;
		case 'l':
			bs->length = strtol(optarg, &endptr, 0);
			if ((bs->length < 0) || (endptr && *endptr))
				bsdsum_log(LL_ERR|LL_FATAL, 
					"bad value for -l");
			break;
		case 'f':
			bs->offset = strtol(optarg, &endptr, 0);
			if ((bs->offset < 0) || (endptr && *endptr))
				bsdsum_log(LL_ERR|LL_FATAL, 
					"bad value for -f");
			break;
		case '?':
			bsdsum_help();
			exit(1);
		}
	}
	if (bs->log) {
		bs->log_fd = open(bs->log, 
				O_CREAT|O_TRUNC|O_WRONLY, 0600);
		if (bs->log_fd < 0)
			bsdsum_log(LL_ERR|LL_FATAL,
				"unable to open log file %s", bs->log);
		bsdsum_log_fd = bs->log_fd;
	}
	bsdsum_log_level = bs->log_lvl;
	if (bs->length >= 0 || bs->offset >= 0) {
		if (bs->style == STYLE_NONE)
			bs->style = STYLE_TERSE;
		else if (bs->style != STYLE_TERSE)
			bsdsum_log(LL_ERR|LL_FATAL, 
					"-f/-l implies -s terse");
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
					bsdsum_log(LL_ERR|LL_FATAL, 
					"unsupported algorithm and/or"
					" style");
				hf = bsdsum_add_op(bs, hf, bs->style);
				if (hf->split >= 2)
					bs->flags |= FLAG_SPLIT;
			}
			break;
		case 'd':
			bs->prepend = optarg;
			break;
		case 'o':
			bs->opath = optarg;
			break;
		case 'C':
			bs->selective_checklist = optarg;
			break;
		case 'c':
			bs->flags |= FLAG_C;
			break;
		case 'k':
			bs->flags |= FLAG_K;
			break;
		case 'p':
			bs->flags |= FLAG_P;
			break;
		case 't':
			bs->flags |= FLAG_T;
			bsdsum_autotest();
			break;
		case 'r':
			bs->flags |= FLAG_R;
			break;
		case 'f':
		case 'l':
		case 's':
		case 'v':
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
	if (bs->log_fd > 0)
		close(bs->log_fd);
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


