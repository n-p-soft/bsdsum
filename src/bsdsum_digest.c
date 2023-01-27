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

void bsdsum_digest_init (bsdsum_op_t *hf, int fd)
{
	if ((hf->ctx = calloc(1, sizeof(bsdsum_ctx_t))) == NULL)
		errx(1, "out of memory");
	memset(hf->digest, 0, sizeof(bsdsum_digest_t));
	hf->digest_fd = fd;
	hf->init(hf->ctx);
}

void bsdsum_digest_end (bsdsum_op_t *hf)
{
	hf->final(hf->digest, hf->ctx);
	if (hf->style & STYLE_TEXT) {
		snprintf(hf->fdigest, sizeof(bsdsum_fdigest_t), 
				"%s", hf->digest);
	}
	else if ((hf->style & STYLE_MASK) == STYLE_BASE64) {
		if (bsdsum_b64_ntop(hf->digest, hf->digestlen, 
				hf->fdigest, sizeof(bsdsum_fdigest_t))
				 == -1)
			errx(1, "error encoding base64");
	}
	else if ((hf->style & STYLE_MASK) == STYLE_MIX32) {
		char *s;
		size_t olen;

		s = bsdsum_enc_32(hf->digest, hf->digestlen,
					SET32_MIX, &olen);
		if (s == NULL)
			errx(1, "mix32 encoding not supported");
		snprintf(hf->fdigest, sizeof(bsdsum_fdigest_t),
				"%s", s);
		free(s);
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

void bsdsum_digest_print (int ofile, const bsdsum_op_t *hf, 
				const char *what)
{
	bsdsum_style_t st = hf->style & STYLE_MASK;
	char alg[32];

	switch (st & STYLE_MASK) {
	case STYLE_NONE:
	default:
		break;
	case STYLE_DEFAULT:
	case STYLE_MIX32:
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
int bsdsum_digest_mmap_file (bsdsum_t *bs, const char *file,
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

int bsdsum_digest_file (bsdsum_t* bs, const char *file, int echo)
{
	bsdsum_op_t *hf;
	size_t nread;
	int std = 0;
	int error;

	if (strcmp(file, "-") == 0)
		std = 1;

	/* process all data */
	if (std) {
		for (hf = bs->hl; hf; hf = hf->next) 
			bsdsum_digest_init(hf, -1);
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
		for (hf = bs->hl; hf; hf = hf->next) 
			bsdsum_digest_end(hf);
	}
	else {
		error = bsdsum_digest_mmap_file(bs, file, bs->hl, 
						bs->offset, bs->length);
		if (error)
			err(error, "could not digest file %s", file);
	}

	for (hf = bs->hl; hf; hf = hf->next) {
		if (std)
			dprintf(bs->ofile, "%s\n", hf->fdigest);
		else
			bsdsum_digest_print(bs->ofile, hf, file);
	}
	return(0);
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

