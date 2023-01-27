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

/*
 * Parse through the input file looking for valid lines.
 * If one is found, use this checksum and file as a reference and
 * generate a new checksum against the file on the filesystem.
 * Print out the result of each comparison.
 */
int bsdsum_dgl_process (bsdsum_t* bs, const char *file, 
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
		st = bsdsum_dgl_parse_line(line, &filename, &checksum, &hf);
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
		case STYLE_COMMENT:
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
		d_error = bsdsum_digest_mmap_file(bs, filename, 
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
	if (*line == '#')
		return STYLE_COMMENT;
	p = strchr(line, ' ');
	if (p == NULL)
		return STYLE_NONE;
	if (p[1] == '(') {
		*p++ = '\0';
		*p++ = '\0';
		*hf = bsdsum_op_find_alg(line, 0, 1);
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
	*hf = bsdsum_op_for_length(strlen(*dg));
	if (*hf == NULL)
		return STYLE_UNSUPPORTED;
	(*hf)->style = st;
	(*hf)->split = 0;
	(*hf)->base64 = 0;
	return st;
}

