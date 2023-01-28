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

/* Initialize one operator. 'fd' is the optional output file
 * descriptor. */
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
	if (hf->style & STYLE_TXT) {
		snprintf(hf->fdigest, sizeof(bsdsum_fdigest_t), 
				"%s", hf->digest);
	}
	else if (hf->style & STYLE_B64) {
		if (bsdsum_b64_ntop(hf->digest, hf->digestlen, 
				hf->fdigest, sizeof(bsdsum_fdigest_t))
				 == -1)
			errx(1, "error encoding base64");
	}
	else if (hf->style & STYLE_M32) {
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
	else if (hf->style & STYLE_BIN) {
		/* nothing */
	}
	else if (hf->style & 
		(STYLE_HEXA | STYLE_GNU | STYLE_CKSUM | STYLE_TERSE)) {
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

/* Output an encoded digest into file 'ofile'. */
void bsdsum_digest_print (int ofile, const bsdsum_op_t *hf, 
				const char *what)
{
	bsdsum_style_t st = hf->style;
	char alg[32];

	if (st & STYLE_TERSE)
		(void)dprintf(ofile, "%s\n", hf->fdigest);
	else if (st & STYLE_BIN)
		(void)write(ofile, hf->digest, hf->digestlen);
	else if (st & (STYLE_M32 | STYLE_B64 | STYLE_HEXA | STYLE_TXT)) {
		if (hf->split >= 2)
			snprintf(alg, 32, "%s:%i", hf->name, hf->split);
		else
			snprintf(alg, 32, "%s", hf->name);
		(void)dprintf(ofile, 
			"%s (%s) = %s\n", alg, what, hf->fdigest);
	}
	else if (st & STYLE_CKSUM)
		(void)dprintf(ofile, "%s %s\n", hf->fdigest, what);
	else if (st & STYLE_GNU)
		(void)dprintf(ofile, "%s  %s\n", hf->fdigest, what);
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
 * offset/length set to -1 are ignored.
 */
int bsdsum_digest_mmap_file (const char *file,
				bsdsum_op_t *hf,
				long offset, long length)
{
	struct stat st;
	void *base;
	size_t len;
	int e, f;
	int r = 0;
	bsdsum_op_t *o;

	//printf("%s %i %i\n", file, offset, length);
	f = open(file, O_RDONLY);
	e = errno;
	if (f < 0) {
		close(f);
		return e;
	}
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

/* Digest one file using algorithms 'ops' and output the result into file
 * 'ofile'.
 */
int bsdsum_digest_file (int ofile, bsdsum_op_t* ops, 
			const char *file, int echo,
			long offset, long length)
{
	bsdsum_op_t *hf;
	size_t nread;
	int std = 0;
	int error;
	unsigned char data[BUFFER_SZK*1024];

	if (strcmp(file, "-") == 0)
		std = 1;

	/* process all data */
	if (std) {
		for (hf = ops; hf; hf = hf->next) 
			bsdsum_digest_init(hf, -1);
		while ((nread = fread(data, 1UL, 
					BUFFER_SZK*1024, stdin)) != 0) {
			if (echo) {
				(void)fwrite(data, nread, 1UL, stdout);
				if (fflush(stdout) != 0)
					err(1, "stdout: write error");
			}
			for (hf = ops; hf; hf = hf->next) {
				hf->update(hf->ctx, 
					(unsigned char*)data, nread);
			}
		}
		for (hf = ops; hf; hf = hf->next) 
			bsdsum_digest_end(hf);
	}
	else {
		error = bsdsum_digest_mmap_file(file, ops, 
						offset, length);
		if (error)
			err(error, "could not digest file %s", file);
	}

	for (hf = ops; hf; hf = hf->next) {
		if (std)
			dprintf(ofile, "%s\n", hf->fdigest);
		else
			bsdsum_digest_print(ofile, hf, file);
	}
	return(0);
}


