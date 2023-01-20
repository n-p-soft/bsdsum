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

bsdsum_op_t functions[] = {
	{
		"SIZE", 16, STYLE_TEXT | STYLE_NOSPLIT,
		(op_init_t)size_init,
		(op_update_t)size_update,
		(op_final_t)size_final,
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
		(op_init_t)sha3_256_begin,
		(op_update_t)sha3_update,
		(op_final_t)sha3_final,
	},
	{
		"SHA3-512", SHA512_DIGEST_LENGTH, STYLE_NONE,
		(op_init_t)sha3_512_begin,
		(op_update_t)sha3_update,
		(op_final_t)sha3_final,
	},
	{
		NULL, 0, 0, NULL,
	}
};

void bsdsum_init(bsdsum_t *bs)
{
	memset(bs, 0, sizeof(bsdsum_t));
	bs->length = -1;
	bs->offset = -1;
	bs->style = STYLE_DEFAULT;
	bs->data = calloc(BUFFER_SZK, 1024);
	bs->ofile = -1;
}

bsdsum_op_t* bsdsum_get_func(const char* name)
{
	int i;

	for (i = 0; functions[i].name; i++)
	{
		if (strcasecmp (functions[i].name, name) == 0)
			return &functions[i];
	}
	return NULL;
}

/* Parse one algorithm name 'cp'. Returns NULL on error.
 * 'base64' may be 1 to ensure the algorithm that is found supports
 * base64 encoding.
 */
bsdsum_op_t* bsdsum_find_alg(const char *cp, int base64, int quiet)
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

	hf = bsdsum_get_func(cp);
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
			warnx("%s doesn't support base64 output", hf->name);
		return NULL;
	}
	hf->split = (int) l;
	return hf;
}

/* copy 'hf' as tail of the list bs->hl and return it */
static bsdsum_op_t* bsdsum_op_add(bsdsum_t *bs, bsdsum_op_t *hf, int base64)
{
	bsdsum_op_t *hftmp;
	bsdsum_op_t *o;

	hftmp = calloc(1, sizeof(*hftmp));
	if (hftmp == NULL)
		err(1, "out of memory");
	*hftmp = *hf;
	hftmp->base64 = base64;
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
static int bsdsum_op_count(bsdsum_t *bs)
{
	bsdsum_op_t *o;
	int n;

	for (n = 0, o = bs->hl; o; o = o->next, n++) { }
	return n;
}

int main(int argc, char **argv)
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
			bsdsum_usage();
			break;
		case 's':
			if (strcasecmp("base64", optarg) == 0)
				bs.style = STYLE_BASE64;
			else if (strcasecmp("gnu", optarg) == 0)
				bs.style = STYLE_GNU;
			else if (strcasecmp("cksum", optarg) == 0)
				bs.style = STYLE_CKSUM;
			else if (strcasecmp("terse", optarg) == 0)
				bs.style = STYLE_TERSE;
			else if (strcasecmp("binary", optarg) == 0)
				bs.style = STYLE_BINARY;
			else if (strcasecmp("default", optarg))
				bsdsum_usage();
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
			bsdsum_usage();
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
				hf = bsdsum_find_alg(cp, bs.base64, 0);
				if (hf == NULL) 
					errx(1, "unsupported algorithm");
				if ((bs.style == STYLE_GNU ||
					bs.style == STYLE_CKSUM) &&
					( ! (hf->style & STYLE_SPACE) ||
					(hf->split >= 2)))
					errx(1, "style not supported for %s",
						cp);
				hf = bsdsum_op_add(&bs, hf, bs.base64);
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
			bsdsum_usage();
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
	if ((bsdsum_op_count(&bs) == 0) && ! bs.cflag && 
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

void bsdsum_digest_init(bsdsum_op_t *hf, int fd)
{
	if ((hf->ctx = calloc(1, sizeof(bsdsum_ctx_t))) == NULL)
		err(1, "out of memory");
	memset(hf->digest, 0, sizeof(bsdsum_digest_t));
	hf->digest_fd = fd;
	hf->init(hf->ctx);
}

void bsdsum_digest_end(bsdsum_op_t *hf)
{
	hf->final(hf->digest, hf->ctx);
	if (hf->style & STYLE_TEXT) {
		snprintf(hf->fdigest, sizeof(bsdsum_fdigest_t), 
				"%s", hf->digest);
	}
	else if ((hf->style & STYLE_MASK) == STYLE_BASE64) {
		if (b64_ntop(hf->digest, hf->digestlen, 
				hf->fdigest, sizeof(bsdsum_fdigest_t)) == -1)
			errx(1, "error encoding base64");
	}
	else if ((hf->style & STYLE_MASK) == STYLE_BINARY) {
		/* nothing */
	} else {
		int i;
		const char* hexa = "0123456789abcdef";

		for (i = 0; i < hf->digestlen; i++) {
			hf->fdigest[2*i]=hexa[hf->digest[i] >> 4];
			hf->fdigest[2*i+1]=hexa[hf->digest[i] & 0xf];
		}
		hf->fdigest[2*i] = 0;
	}
	if (hf->digest_fd >= 0) {
		if (write(hf->digest_fd, 
			hf->digest, hf->digestlen) != hf->digestlen)
			err(1, "could not store digest into temporary "
				"file");
	}
	free(hf->ctx);
	hf->ctx = NULL;
}

void digest_print(int ofile, const bsdsum_op_t *hf, 
			const char *what)
{
	bsdsum_style_t st = hf->style & STYLE_MASK;
	char alg[32];

	switch (st & STYLE_MASK) {
	case STYLE_NONE:
	default:
		break;
	case STYLE_DEFAULT:
	case STYLE_BASE64:
		if (hf->split >= 2)
			snprintf(alg, 32, "%s:%i", hf->name, hf->split);
		else
			snprintf(alg, 32, "%s", hf->name);
		(void)dprintf(ofile, 
			"%s (%s) = %s\n", alg, what, hf->fdigest);
		break;
	case STYLE_CKSUM:
		(void)dprintf(ofile, "%s %s\n", hf->fdigest, what);
		break;
	case STYLE_GNU:
		(void)dprintf(ofile, "%s  %s\n", hf->fdigest, what);
		break;
	case STYLE_BINARY:
		(void)write(ofile, hf->digest, hf->digestlen);
		break;
	case STYLE_TERSE:
		(void)dprintf(ofile, "%s\n", hf->fdigest);
		break;
	}
}

/* compute one digest for (buf,length) and operator 'hf'. */
int bsdsum_digest_run (bsdsum_op_t *hf,
			unsigned char* buf, long length,
			int split)
{
	int i, status, nchilds, allok;
	size_t slen;
	long off = 0;
	int fds[MAX_SPLIT];
	pid_t pids[MAX_SPLIT];
	unsigned char *cdg;
	char tmp[MAX_SPLIT][20];
	pid_t r;

	//printf("%i %p %li %i\n", getpid(), buf, length, split);
	if (split < 2) {
		bsdsum_digest_init(hf, -1);
		hf->update(hf->ctx, buf, length);
		bsdsum_digest_end(hf);
		return(0);
	}

	/* split digest */
	cdg = calloc(hf->split, hf->digestlen);
	if (cdg == NULL)
		errx(1, "out of memory");
	for (i = 0; i < hf->split; i++) {
		snprintf(tmp[i], 20, "/tmp/bsdsumXXXXXX");
		fds[i] = mkstemp(tmp[i]);
		if (fds[i] < 0)
			err(1, "cannot create temporary file");
	}
	signal(SIGCHLD, SIG_DFL);
	slen = length / split;
	for (i = 0; i < hf->split; i++) {
		if (i == hf->split - 1)
			slen = length;
		else
			length -= slen;
		pids[i] = fork();
		if (pids[i] < 0) 
			errx(1, "could not fork");
		else if (pids[i] == 0) {
			if (bsdsum_digest_run(hf, buf + off, slen, 0))
				exit(1);
			if (write(fds[i], hf->digest, hf->digestlen) !=
							hf->digestlen)
				exit(1);
			exit(0);
		}
		off += slen;
	}

	/* wait for childs */
	/* TODO: check for stalled childs */
	for (allok = 1, nchilds = hf->split; nchilds; ) {
		r = waitpid(-1, &status, WNOHANG);
		if (r <= 0) {
			usleep(10000);
			continue;
		}
		for (i = 0; i < hf->split; i++) {
			if (pids[i] != r)
				continue;
			nchilds--;
			pids[i] = -1;
			if ( ! WIFEXITED(status))
				allok = 0;
		}		
	}
	for (i = 0; i < hf->split; i++) {
		if (pids[i] != -1)
			kill(pids[i], SIGKILL);
	}
	if ( ! allok)
		errx(1, "split digest failure");
	for (i = 0; i < hf->split; i++) {
		if ((lseek(fds[i], 0, SEEK_SET) != 0) ||
			(read(fds[i], cdg+i*hf->digestlen, hf->digestlen) !=
						hf->digestlen))
			errx(1, "unable to read split-digest results");
		close(fds[i]);
		unlink(tmp[i]);
	}
	bsdsum_digest_run(hf, cdg, hf->digestlen * hf->split, 0);
	free(cdg);
	return(0);
}

/* Try to mmap given file and digest it. 
 * The function returns errno on error, or 0 on success, or
 * does not return on erroneous offset/length parameters.
 * offset/length set to -1 is ignored.
 */
static int bsdsum_mmap_digest_file(bsdsum_t *bs, const char *file,
					bsdsum_op_t *hf,
					long offset, long length)
{
	struct stat st;
	void *base;
	size_t len;
	int e;
	int r = 0;
	bsdsum_op_t *o;

	//printf("%s %i %i\n", file, offset, length);
	int f = open(file, O_RDONLY);
	e = errno;
	if (f < 0) {
		close(f);
		return e;
	}
	bs->current_file = file;
	if (fstat(f, &st)) {
		e = errno;
		close(f);
		return e;
	}

	/* cannot mmap a file of size zero */
	if (st.st_size == 0) {
		unsigned char dummy = 0;
	
		close(f);
		for (o = hf; o; o = o->next) 
			r |= bsdsum_digest_run(o, &dummy, 0, o->split);
		return(r);
	}

	base = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
	if (base == (void*)-1) {
		e = errno;
		close(f);
		return e;
	}
	else if (offset <= 0) {
		offset = 0;
		len = (length >= 0) ? length : st.st_size;
		if (len > st.st_size)
			errx(1, "bad length specified");
	}
	else {
		if (length < 0) {
			if (offset > st.st_size)
				errx(1, "bad offset specified");
			len = st.st_size - offset;
		}
		else {
			if (offset + length > st.st_size)
				errx(1, "bad offset/length specified");
			len = length;
		}
	}

	for (o = hf; o; o = o->next) 
		r |= bsdsum_digest_run(o, base + offset, len, o->split);
	munmap(base, st.st_size);
	close(f);
	return(r);
}

int bsdsum_digest_file(bsdsum_t* bs, const char *file, int echo)
{
	bsdsum_op_t *hf;
	size_t nread;
	int std = 0;
	int error;

	if (strcmp(file, "-") == 0)
		std = 1;

	/* process all data */
	if (std) {
		while ((nread = fread(bs->data, 1UL, 
					BUFFER_SZK*1024, stdin)) != 0) {
			if (echo) {
				(void)fwrite(bs->data, nread, 1UL, stdout);
				if (fflush(stdout) != 0)
					err(1, "stdout: write error");
			}
			for (hf = bs->hl; hf; hf = hf->next) {
				hf->update(hf->ctx, 
					(unsigned char*)bs->data, nread);
			}
		}
	}
	else {
		error = bsdsum_mmap_digest_file(bs, file, bs->hl, 
						bs->offset, bs->length);
		if (error)
			err(error, "could not digest file %s", file);
	}

	for (hf = bs->hl; hf; hf = hf->next) {
		if (std)
			dprintf(bs->ofile, "%s\n", hf->fdigest);
		else
			digest_print(bs->ofile, hf, file);
	}
	return(0);
}

/* find the line format:
 * Possible forms:
 *  ALGORITHM (FILENAME) = CHECKSUM
 *  CHECKSUM  FILENAME
 *  CHECKSUM FILENAME
 * Returns STYLE_ or -1 on error.
 */
bsdsum_style_t bsdsum_parse(char *line, char **filename, char **dg,
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
		*hf = bsdsum_find_alg(line, 0, 1);
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
	for (i = 0; functions[i].name; i++) {
		if ( ! (functions[i].use_style & STYLE_SPACE))
			continue;
		if (len == functions[i].digestlen * 2)
			break;
	}
	if (functions[i].name == NULL)
		return STYLE_UNSUPPORTED;
	*hf = &functions[i];
	(*hf)->style = st;
	(*hf)->split = 0;
	(*hf)->base64 = 0;
	return st;
}

/* read a line, max 1KB. Returns NULL only on error. */
static char* bsdsum_getline(int fd, int* eof, const char *filename)
{
	const int max = 1024;
	char *l = calloc(1, max);
	int n;
	char c;

	if (l == NULL)
		errx(1, "out of memory");
	*eof = 0;
	for (n = 0; n < max; n++) {
		switch (read(fd, &c, 1)) {
		case 0:
			*eof = 1;
			return l;
		case 1:
			l[n] = c;
			if (c == '\n')
				return l;
			break;
		default:
			warnx("I/O error reading %s", filename);
			free(l);
			return NULL;
		}
	}
	free(l);
	warnx("line too long in %s", filename);
	return NULL;
}

/*
 * Parse through the input file looking for valid lines.
 * If one is found, use this checksum and file as a reference and
 * generate a new checksum against the file on the filesystem.
 * Print out the result of each comparison.
 */
int bsdsum_digest_filelist(bsdsum_t* bs, const char *file, 
				bsdsum_op_t *defhash, 
				int selcount, char **sel)
{
	int d_error, cmp, i;
	char *filename, *checksum, *line;
	ssize_t linelen;
	int listfd;
	int eof = 0;
	int std = 0;
	size_t len, linesize, nread;
	int lineno = 0;
	int fmterr = 0;
	int skipped = 0;
	int *sel_found = NULL;
	bsdsum_op_t *hf;
	bsdsum_style_t st;
	char algorithm[16];
	int skip;

	if (strcmp(file, "-") == 0) {
		listfd = 0;
		std = 1;
	} else if ((listfd = open(file, O_RDONLY)) < 0) {
		warn("cannot open %s", file);
		return(1);
	}

	if (sel != NULL) {
		sel_found = calloc((size_t)selcount, sizeof(*sel_found));
		if (sel_found == NULL)
			err(1, NULL);
	}

	bs->error = 0;
	line = NULL;
	linesize = 0;
	while(eof == 0) {
		line = bsdsum_getline(listfd, &eof, file);
		if (eof && ( ! line || ! *line))
			break;
		if (line == NULL) {
			bs->error++;
			break;
		}
		lineno++;
		st = bsdsum_parse(line, &filename, &checksum, &hf);
		skip = 0;
		switch (st) {
		case STYLE_UNSUPPORTED:
			warnx("line %i: unsupported algorithm", lineno);
			bs->error++;
			skip = 1;
			break;
		case STYLE_ERROR:
			warnx("line %i: format not recognized", lineno);
			fmterr++;
			skip = 1;
			break;
		case STYLE_NONE:
			warnx("line %i: skipping", lineno);
			skip = 1;
			break;
		default:
			if (defhash && hf != defhash)
				skip = 1;
			break;
		}
		if (skip) {
			skipped++;
			free(line);
			continue;
		}
		//printf("%x <%s> <%s>\n", st, filename, checksum);

		/* If only a selection of files is wanted, proceed only
		 * if the filename matches one of those in the selection. */
		if (sel != NULL) {
			for (i = 0; i < selcount; i++) {
				if (strcmp(sel[i], filename) == 0) {
					sel_found[i] = 1;
					break;
				}
			}
			if (i == selcount)
				continue;
		}
		if (hf->split >= 2)
			snprintf(algorithm, 16,
				"%s:%i", hf->name, hf->split);
		else
			snprintf(algorithm, 16, "%s", hf->name);

		/* hash the file */
		d_error = bsdsum_mmap_digest_file(bs, filename, 
							hf, -1, -1);
		if (d_error) {
			printf("(%s) %s: %s\n", algorithm, filename,
			    (d_error == ENOENT ? "MISSING" : "FAILED"));
			if (d_error != ENOENT)
				warnx("cannot digest %s", filename);
			bs->error++;
		}
		else {
			if (hf->base64)
				cmp = strcmp(checksum, hf->fdigest);
			else
				cmp = strcasecmp(checksum, hf->fdigest);
			if (cmp == 0) {
				(void)printf("(%s) %s: OK\n", algorithm,
					    filename);
			} else {
				(void)printf("(%s) %s: FAILED\n", 
						algorithm, filename);
				bs->error++;
			}
		}
		free(line);
	}
	if (std == 0)
		close(listfd);
	if (skipped) {
		warnx("%s: %i line(s) skipped", file, skipped);
		bs->error++;
	}
	if (fmterr) {
		warnx("%s: found ill-formatted checksum line(s)", file);
		bs->error++;
	}
	if (sel_found != NULL) {
		/* Mark found files by setting them to NULL so that we can
		 * detect files that are missing from the checklist later. */
		for (i = 0; i < selcount; i++) {
			if (sel_found[i])
				sel[i] = NULL;
		}
		free(sel_found);
	}
	if (bs->error)
		warnx("%s: %i error(s)", file, bs->error);
	return(bs->error);
}

/*****************************************************************************
 * HELP                                                                      *
 *****************************************************************************/
void
bsdsum_usage(void)
{
	fprintf(stderr, 
	"usage: bsdsum v" VERSION " - compute and check digests\n"
	"        [-h] show this help\n"
	"        [-t] only run a simple auto-test\n"
	"        [-p] echoes stdin to stdout and appends checksum\n"
	"             to stdout\n"
        "        [-s STYLE] output format, one of:\n"
	"             default: \"ALG (FILE) = RESULT\"\n"
	"             base64: \"ALG (FILE) = BASE64_RESULT\"\n"
	"             cksum: \"RESULT FILE\" (one space)\n"
	"             gnu: \"RESULT  FILE\" (two spaces)\n"
	"             terse: \"RESULT\" (hexadecimal, no file)\n"
	"             binary: \"RESULT\" (raw binary, no file)\n"
	"        [-a ALG] digest algorithm or operation to apply (may be a\n"
	"             comma-separated list unless -c/-C is used):\n"
	"             'MD5' compute MD5 digest\n"
	"             'SHA1' compute SHA-1 digest\n"
	"             'SHA256' compute SHA2-256 digest\n"
	"             'SHA384' compute SHA2-384 digest\n"
	"             'SHA512' compute SHA2-512 digest\n"
	"             'SHA3-256' compute SHA3-256 digest (Keccak 1600)\n"
	"             'SHA3-512' compute SHA3-512 digest (Keccak 1600)\n"
	"             'SIZE' count length of data (as in 'distinfo' files)\n"
	"             'ALG:N' with ALG one of the algorithms above, \n"
	"                     excepted SIZE, and N an integer between 2 and\n"
	"                     16, to run a split-digest. Source file is split\n"
	"                     into N parts and each part is hashed using a\n"
	"                     separate thread to produce digest H(i). Then\n"
	"                     all digests H(i) are concatenated and digest\n"
	"                     of this block is output as the file's digest.\n" 
	"                     This process is not usable with stdin or -p.\n"
	"                     Supported styles are 'default' and 'base64'.\n"
	"        [-l] optional length of data to digest when one, and\n"
	"             only one file to digest is specified. Implies\n"
	"             -s terse\n"
	"        [-f] optional offset where to start when one, and\n"
	"             only one file to digest is specified. Implies\n"
	"             -s terse\n"
	"        [-c] 'file' is a checklist\n"
	"        [-C checklist] bsdsum_compare the checksum of 'file' against\n"
	"                       checksums in 'checklist'\n"
	"        [-o hashfile] place the checksum into this file\n"
	"                      instead of stdout\n"
	"        [file ...]\n");

	exit(EXIT_FAILURE);
}


void explicit_bzero(void* p, size_t sz)
{
	unsigned char* q = p;
	size_t i;

	if ( ! p)
		return;
	for (i = 0; i < sz; i++)
		*q++ = 0;
}

