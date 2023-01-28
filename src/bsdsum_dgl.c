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

/* read a line, max 1KB. Returns NULL only on error. */
static char* bsdsum_dgl_getline(int fd, int* eof, const char *filename)
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
			free(l);
			return NULL;
		}
	}
	free(l);
	return NULL;
}

/* Initialize parameters block for list processing. User must provide
 * either 'path' (set to "-" for stdin) or 'listfd' (set to -1 to
 * disable it).
 */
bsdsum_dgl_par_t *bsdsum_dgl_start(bsdsum_dgl_cmd_t cmd,
					bsdsum_flag_t flags,
					int listfd, const char *path)
{
	bsdsum_dgl_par_t* par;

	if (path && (listfd >= 0))
		return NULL;

	par = calloc(1, sizeof(bsdsum_dgl_par_t));
	if (par == NULL)
		err(1, NULL);

	par->cmd = cmd;
	par->flags = flags;
	if (path) {
		par->path = path;
		par->listfd = -1;
	}
	else
		par->listfd = listfd;

	return par;
}

/* De-init a list processing, setting *par to NULL. */
void bsdsum_dgl_end(bsdsum_dgl_par_t** par)
{
	if ( ! par || ! *par)
		return;

	if ((*par)->files_found)
		free((*par)->files_found);

	free(*par);
	*par = NULL;
}

/* check a lit of digests. */
static bsdsum_dgl_res_t bsdsum_dgl_check_line(bsdsum_dgl_par_t *par, 
						char *line)
{
	int d_error, cmp, i;
	char *filename, *checksum;
	ssize_t linelen;
	size_t len, linesize, nread;
	bsdsum_op_t *hf;
	bsdsum_style_t st;
	char algorithm[32];
	int skip = 0;

	st = bsdsum_dgl_parse_line(line, &filename, &checksum, &hf);
	if (st == STYLE_UNSUPPORTED) {
		warnx("line %i: unsupported algorithm", 
			par->lineno);
		par->l_error++;
		return DGL_RES_CONTINUE;
	}
	else if (st == STYLE_ERROR) {
		warnx("line %i: format not recognized", 
			par->lineno);
		par->l_syntax++;
		return DGL_RES_CONTINUE;
	}
	else if (st == STYLE_COMMENT) {
		par->l_comment++;
		return DGL_RES_CONTINUE;
	}
	else if (st == STYLE_NONE) {
		par->l_empty++;
		return DGL_RES_CONTINUE;
	}
	else if (par->algs && hf != par->algs) {
		par->l_skipped++;	
		return DGL_RES_CONTINUE;
	}

	/* filter-out some files */
	if (par->files != NULL) {
		for (i = 0; i < par->files_count; i++) {
			if (strcmp(par->files[i], filename) == 0) {
				par->files_found[i] = 1;
				break;
			}
		}
		if (i == par->files_count)
			return DGL_RES_CONTINUE;
	}

	if (hf->split >= 2)
		snprintf(algorithm, 32, "%s:%i", hf->name, hf->split);
	else
		snprintf(algorithm, 32, "%s", hf->name);

	/* hash the file */
	d_error = bsdsum_digest_mmap_file(filename,  hf, -1, -1);
	if (d_error) {
		printf("(%s) %s: %s\n", algorithm, filename,
		    (d_error == ENOENT ? "MISSING" : "FAILED"));
		if (d_error != ENOENT)
			warnx("cannot digest %s", filename);
		par->l_error++;
	}
	else {
		if (bsdsum_op_case_sensitive(hf->style))
			cmp = strcmp(checksum, hf->fdigest);
		else
			cmp = strcasecmp(checksum, hf->fdigest);
		if (cmp == 0) {
			(void)printf("(%s) %s: OK\n", algorithm,
				    filename);
			par->l_ok++;
		} else {
			(void)printf("(%s) %s: FAILED\n", 
					algorithm, filename);
			par->l_error++;
		}
	}
}

typedef bsdsum_dgl_res_t (*bsdsum_dgl_cb_t) (bsdsum_dgl_par_t* par,
						char *line);

/* process each line using callback 'cb'. */
static bsdsum_dgl_res_t bsdsum_dgl_read(bsdsum_dgl_par_t *par,
					bsdsum_dgl_cb_t cb)
{
	int eof = 0;
	char *line;
	bsdsum_dgl_res_t res = DGL_RES_OK;
	bsdsum_dgl_res_t lres;

	while(eof == 0) {
		line = bsdsum_dgl_getline(par->listfd, &eof, par->path);
		if (eof && ( ! line || ! *line))
			break;
		if (line == NULL) {
			res = DGL_RES_ERR_IO;
			break;
		}
		par->lineno++;
		if (*line == 0) {
			par->l_empty++;
			continue;
		}
		if (*line == '#') {
			par->l_comment++;
			continue;
		}
		lres = cb(par, line);
		if (lres & DGL_RES_ERROR)
			res |= DGL_RES_ERROR;
		if (lres & DGL_RES_BREAK)
			break;
	}

	if (par->l_error)
		res |= DGL_RES_ERROR;

	return res;
}

/* Hash par->files. */
static bsdsum_dgl_res_t bsdsum_dgl_hash(bsdsum_dgl_par_t *par)
{
	bsdsum_dgl_res_t res = DGL_RES_OK;
	int i;
	struct stat st;

	for (i = 0; i < par->files_count; i++) {
		if (stat(par->files[i], &st)) {
			res = DGL_RES_ERROR;
			warnx("unable to stat file %s\n",
					par->files[i]);
			continue;
		}
		switch(st.st_mode & S_IFMT) {
		case S_IFREG:
			if (bsdsum_digest_file(par->listfd,
					par->algs, par->files[i],
					(par->flags & FLAG_P) ? 1 : 0,
					-1, -1))
				par->l_error++;
			break;
		case S_IFDIR:
			/* TODO: if (par->flags & FLAG_R) {
			}
			else */ {
				warnx("skipping directory %s",
					par->files[i]);
				par->l_skipped++;
			}
			break;
		case S_IFBLK:
		case S_IFCHR:
		case S_IFIFO:
		case S_IFLNK:
		case S_IFSOCK:
			warnx("unsupported file type %s",
					par->files[i]);
			par->l_skipped++;
			break;
		}
	}
}

/* Process some DGL_CMD. */
bsdsum_dgl_res_t bsdsum_dgl_process(bsdsum_dgl_par_t *par)
{
	bsdsum_dgl_res_t res = DGL_RES_OK;
	bsdsum_dgl_res_t lres;
	int fd = -1;
	int fflags;

	if (par == NULL) {
		warnx("missing parameters");
		return DGL_RES_ERR_PAR;
	}	

	/* open the digests list (input) or the output */
	if (par->cmd == DGL_CMD_HASH)
		fflags = O_CREAT|O_APPEND|O_WRONLY;
	else
		fflags = O_RDONLY;

	if (par->listfd < 0) {
		if (strcmp(par->path, "-") == 0) {
			par->listfd = 0;
			par->std = 1;
		} else if (par->path == NULL) {
			warnx("missing target path");
			return DGL_RES_ERR_PAR;
		} else {
			par->listfd = open(par->path, fflags);
			if (par->listfd < 0) {
				warn("cannot open %s", par->path);
				return DGL_RES_ERR_IO;
			}
		}
	}
	else
		fd = par->listfd;

	par->l_error = 0;
	par->l_syntax = 0;
	par->l_comment = 0;
	par->l_empty = 0;
	par->l_ok = 0;
	par->lineno = 0;

	/* initialize the found flag list */
	if ((par->cmd == DGL_CMD_CHECK) && (par->files != NULL)) {
		par->files_found = calloc((size_t)par->files_count, 
						sizeof(int));
		if (par->files_found == NULL)
			err(1, NULL);
	}

	/* run the command */
	switch(par->cmd) {
		case DGL_CMD_CHECK:
			/* check the digests in the list, possibly using
			 * the selector par->files. */
			res = bsdsum_dgl_read(par,
						bsdsum_dgl_check_line);
			break;
		case DGL_CMD_HASH:
			/* compute the digests of par->files and output
			 * to par->listfd. */
			res = bsdsum_dgl_hash(par);
			break;
		case DGL_CMD_HASH_STDIN:
			if (bsdsum_digest_file(par->listfd, par->algs,
					"-",
					(par->flags & FLAG_P) ? 1 : 0,
					-1, -1))
				res = DGL_RES_ERROR;
			break;
		default:
			res = DGL_RES_ERR_PAR;
			break;
	}

	/* close the list */
	if (fd < 0) {
		if ( ! par->std)
			close(par->listfd);
		par->listfd = -1;
	}

	if (par->l_skipped) {
		if (par->path)
			warnx("%s: %i item(s) skipped", 
					par->path, par->l_skipped);
		else
			warnx("%i item(s) skipped", 
				par->l_skipped);
	}
	if (par->l_syntax) {
		if (par->path)
			warnx("%s: found %i ill-formatted line(s)", 
					par->path, par->l_syntax);
		else
			warnx("found %i ill-formatted line(s)", 
					par->l_syntax);
		/* force one error for these lines */
		res |= DGL_RES_ERROR;
	}

	/* raise an error if some selected files were not encountered. */
	if (par->files_found) {
		int i;

		for (i = 0; i < par->files_count; i++) {
			if (par->files_found[i] == 0) {
				warnx("%s was not found",
					par->files[i]);
				res |= DGL_RES_ERROR;
			}
		}
	}

	return res;
}

/* check for an hexadecimal string of length 'len' bytes */
static bool bsdsum_dgl_is_hex(const char *s, size_t blen)
{
	int i;

	if (strlen(s) != 2*blen)
		return false;
	for (i = 0; i < 2*blen; i++) {
		if ((s[i] >= '0') && (s[i] <= '9'))
			continue;
		if ((s[i] >= 'a') && (s[i] <= 'f'))
			continue;
		if ((s[i] >= 'A') && (s[i] <= 'F'))
			continue;
		return false;
	}
	return true;
}

/* try to parse one "ALG (file) = DG" line.
 * 'p' is a pointer to the first space of the line.
 */
static bsdsum_style_t bsdsum_dgl_parse_bsd_line (char *line, char *p, 
					char **filename, char **dg,
					bsdsum_op_t **hf)
{
	bsdsum_style_t st;

	*p++ = '\0';
	*p++ = '\0';
	*hf = bsdsum_op_find_alg(line, 0, 1);
	if (*hf == NULL)
		return STYLE_UNSUPPORTED;
	(*hf)->style = STYLE_NONE;
	*filename = p;
	p = strchr(p, ')');
	if (p == NULL)
		return STYLE_ERROR;
	*p++ = 0;
	if ((p[0] != ' ') || (p[1] != '=') || (p[2] != ' '))
		return STYLE_ERROR;
	*dg = p + 3;

	/* may be a non-encoded value such as SIZE */
	if ((*hf)->use_style & STYLE_TXT) {
		(*hf)->style |= STYLE_TXT;
		return (*hf)->style;
	}

	/* test if we have our 5-bit encoding. There is no risk
	 * to make an error because the length of such digests is
	 * special. */
	st = bsdsum_enc_test(*dg, (*hf)->digestlen);
	if ((st != STYLE_ERROR) && (st != STYLE_NONE)) {
		(*hf)->style |= st;
		return (*hf)->style;
	}

	/* check for base64 */
	if (bsdsum_b64_test(*dg, (*hf)->digestlen)) {
		(*hf)->style |= STYLE_B64;
		return (*hf)->style;
	}

	/* here we should have an hexadecimal string */
	if (bsdsum_dgl_is_hex(*dg, (*hf)->digestlen)) {
		(*hf)->style |= STYLE_HEXA;
		return (*hf)->style;
	}

	return STYLE_ERROR;
}

/* try to parse a gnu/cksum line: DIGEST SPACE(S) FILE.
 * 'p' is a pointer to the first space of 'line'.
 */
static bsdsum_style_t bsdsum_dgl_parse_gnu_line(char *line, char *p,
					char **filename, char **dg,
					bsdsum_op_t **hf)
						
{
	bsdsum_style_t st;

	*dg = line;
	*p++ = '\0';
	if (*p == ' ') {
		st = STYLE_GNU;
		p++;			
	}
	else
		st = STYLE_CKSUM;

	/* FIXME: should we eat all spaces ? */
	*filename = p;
	*hf = bsdsum_op_for_length(strlen(*dg));
	if (*hf == NULL)
		return STYLE_UNSUPPORTED;
	if ( ! bsdsum_dgl_is_hex(*dg, (*hf)->digestlen))
		return STYLE_ERROR;
	(*hf)->split = 0;
	return st;
}

/* find the line format. Possible forms:
 *  ALGORITHM (FILENAME) = CHECKSUM
 *  CHECKSUM  FILENAME
 *  CHECKSUM FILENAME
 * Returns STYLE_xxx.
 */
bsdsum_style_t bsdsum_dgl_parse_line (char *line, 
					char **filename, char **dg,
					bsdsum_op_t **hf)
{
	char *p;

	*hf = NULL;
	*filename = *dg = NULL;
	if (line == NULL)
		return STYLE_NONE;
	p = strchr(line, '\n');
	if (p)
		*p = '\0';
	if (*line == '\0')
		return STYLE_NONE;
	if (*line == '#')
		return STYLE_COMMENT;
	p = strchr(line, ' ');
	if (p == NULL)
		return STYLE_NONE;
	if (p[1] == '(')  {
		/* BSD style */
		return bsdsum_dgl_parse_bsd_line(line, p, filename, dg, hf);
	}
	else {
		/* GNU/cksum style */
		return bsdsum_dgl_parse_gnu_line(line, p, filename, dg, hf);
	}
}

