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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>

#include "bsdsum.h"

/* Initialize one operator. 'fd' is the optional output file
 * descriptor. */
void bsdsum_digest_init (bsdsum_op_t *hf, int fd)
{
	if ((hf->ctx = calloc(1, sizeof(bsdsum_ctx_t))) == NULL)
		bsdsum_log(LL_ERR|LL_FATAL, "out of memory");
	memset(hf->digest, 0, sizeof(bsdsum_digest_t));
	hf->digest_fd = fd;
	hf->init(hf->ctx);
}

/* end a digest and produce the encoded result into hf->fdigest */
bsdsum_res_t bsdsum_digest_end (bsdsum_op_t *hf)
{
	hf->final(hf->digest, hf->ctx);
	if (hf->style & STYLE_TXT) {
		snprintf(hf->fdigest, sizeof(bsdsum_fdigest_t), 
				"%s", hf->digest);
	}
	else if (hf->style & STYLE_B64) {
		if (bsdsum_b64_ntop(hf->digest, hf->digestlen, 
				hf->fdigest, sizeof(bsdsum_fdigest_t))
				 == -1) {
			bsdsum_log(LL_ERR, "error encoding base64");
			return RES_ERROR;
		}
	}
	else if (hf->style & STYLE_M32) {
		char *s;
		size_t olen;

		s = bsdsum_enc_32(hf->digest, hf->digestlen,
					SET32_MIX, &olen);
		if (s == NULL) {
			bsdsum_log(LL_ERR, "mix32 encoding failure");
			free(s);
			return RES_ERROR;
		}
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
			hf->digest, hf->digestlen) != hf->digestlen) {
			bsdsum_log(LL_ERR, 
				"could not store digest into temporary "
				"file");
			return RES_ERROR;
		}
	}
	free(hf->ctx);
	hf->ctx = NULL;
	return RES_OK;
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


/* read from 'fd' 'length' bytes starting at 'offset' and
 * process this data with 'hf': this algorithm only if
 * 'first_only' is true, else the list starting at 'hf',
 * selecting only non-split digests if 'nosplit_only' is true.
 * Assume that 'fd', 'offset', 'length' are valid.
 */
static bsdsum_res_t bsdsum_digest_read(int fd, bsdsum_op_t *hf,
					bool first_only,
					bool nosplit_only,
					off_t offset, off_t length)
{
	ssize_t rd;
	off_t len;
	bsdsum_op_t* o;
	static unsigned char *readbuf = NULL;

	if (readbuf == NULL) {
		readbuf = malloc(BUFFER_RAW_SZK*1024);
		if (readbuf == NULL)
			bsdsum_log(LL_ERR|LL_FATAL,
					"cannot allocate read buffer");
	}

	if (lseek(fd, offset, SEEK_SET) != offset) {
		bsdsum_log(LL_ERR, "could not seek file");
		return RES_ERROR;
	}

	while(length > 0) {
		len = (length < BUFFER_RAW_SZK*1024) ? 
			length : BUFFER_RAW_SZK*1024;
		rd = read(fd, readbuf, len);
		if (rd <= 0) {
			close(fd);
			bsdsum_log(LL_ERR, "could not read file");
			return RES_ERROR;
		}
		for (o = hf; o; o = o->next) {
			if (nosplit_only && (o->split > 1))
				continue;	
			o->update(o->ctx, readbuf, len);
			if (first_only)
			       break;
		}
		length -= len;
	}
	for (o = hf; o; o = o->next) {
		if (nosplit_only && (o->split > 1))
			continue;	
		if (bsdsum_digest_end(o) != RES_OK)
			return RES_ERROR;
		if (first_only)
		       break;
	}
	return RES_OK;
}

/* compute split-digest for ONE algorithm 'hf', using as data
 * source either 'file', if non-NULL, else 'buf'. 'offset' and
 * 'length' must be valid. 
 */
static bsdsum_res_t bsdsum_digest_split(bsdsum_op_t *hf,
					const char* file,
					unsigned char *buf,
					off_t offset, off_t length)
{
	int fd, i, status, nchilds, allok;
	size_t slen;
	off_t off = offset;
	int fds[MAX_SPLIT];
	pid_t pids[MAX_SPLIT];
	unsigned char *cdg;
	char tmp[MAX_SPLIT][20];
	pid_t r;
	bsdsum_res_t res = RES_OK;

	cdg = calloc(hf->split, hf->digestlen);
	if (cdg == NULL)
		bsdsum_log(LL_ERR|LL_FATAL, "out of memory");
	for (i = 0; i < hf->split; i++) {
		snprintf(tmp[i], 20, "/tmp/bsdsumXXXXXX");
		fds[i] = mkstemp(tmp[i]);
		if (fds[i] < 0) {
			bsdsum_log(LL_ERR, 
				"could not create temporary file");
			return RES_ERROR;
		}
	}
	signal(SIGCHLD, SIG_DFL);
	slen = length / hf->split;
	for (i = 0; i < hf->split; i++) {
		if (i == hf->split - 1)
			slen = length;
		else
			length -= slen;
		pids[i] = fork();
		if (pids[i] < 0) {
			bsdsum_log(LL_ERR, "could not fork");
			res = RES_ERROR;
			break;
		}
		else if (pids[i] == 0) { /* child */
			if (buf) {
				if (bsdsum_digest_mem(hf, buf + off, 
							slen, 0) != RES_OK)
					exit(1);
			}
			else {
				fd = open(file, O_RDONLY);
				if (fd < 0) {
					bsdsum_log(LL_ERR, 
						"could not open %s", file);
					exit(1);
				}
				if (bsdsum_digest_read(fd, hf, true, false,
							off, slen) != RES_OK) {
					close(fd);
					exit(1);
				}
				close(fd);
			}
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
	if ( ! allok) {
		bsdsum_log(LL_ERR, "split digest failure");
		res = RES_ERROR;
	}
	for (i = 0; i < hf->split; i++) {
		if ((lseek(fds[i], 0, SEEK_SET) != 0) ||
			(read(fds[i], cdg+i*hf->digestlen, hf->digestlen) !=
						hf->digestlen)) {
			bsdsum_log(LL_ERR, 
				"unable to read split-digest results");
			res = RES_ERROR;
		}
		close(fds[i]);
		unlink(tmp[i]);
	}
	if (res == RES_OK) 
		res = bsdsum_digest_mem(hf, cdg, 
					hf->digestlen * hf->split, 0);
	free(cdg);
	return res;
}

/* Compute all digests for the list 'hf', reading directly 'file'.
 * We assume that 'offset' and 'length' have been checked before and
 * are valid.
 */
static bsdsum_res_t bsdsum_digest_file(const char* file, 
					bsdsum_op_t* hf,
					off_t offset, off_t length)
{
	int fd;
	bsdsum_op_t *o;
	off_t len, savlen;
       
	fd = open(file, O_RDONLY);
	if (fd < 0) {
		bsdsum_log(LL_ERR, "could not open %s", file);
		return RES_ERROR;
	}

	for (o = hf; o; o = o->next)
		bsdsum_digest_init(o, -1);

	/* first, run all non-split digests: this avoids reading
	 * the file many times. */
	savlen = length;
	if (bsdsum_digest_read(fd, hf, false, true,
				offset, length) != RES_OK) {
		close(fd);
		return RES_ERROR;
	}
	close(fd);

	/* for split-digests we must re-read the file for each algorithm */
	for (o = hf; o; o = o->next) {
		if (o->split <= 1)
			continue;
		if (bsdsum_digest_split(hf, file, NULL, offset, length) !=
				RES_OK)
			return RES_ERROR;
	}

	return RES_OK;
}

/* compute ONE digest 'hf' for (buf,length) in memory.
 * 'offset' and 'length' must be valid. The 'split' value will
 * override hf->split.
 * If RES_OK is returned then hf->digest and hf->fdigest are set. */
bsdsum_res_t bsdsum_digest_mem (bsdsum_op_t *hf, 
				unsigned char* buf, off_t length,
				int split)
{
	bsdsum_res_t res = RES_OK;

	DBG("digest_mem: %i %p %zi %i\n", getpid(), buf, length, split);
	if (split < 2) {
		bsdsum_digest_init(hf, -1);
		hf->update(hf->ctx, buf, length);
		return bsdsum_digest_end(hf);
	}
	else
		return bsdsum_digest_split(hf, NULL, buf, 0, length);
}

/* Hash a file, using mmap (fallback to buffered read if not possible),
 * for all operators in list 'hf'.  
 * 'stsrc' can be provided for 'file' or be NULL to stat it now.
 * 'offset'/'length' set to -1 are ignored.
 */
static bsdsum_res_t bsdsum_digest_reg (const char *file,
					struct stat *stsrc,
					bsdsum_op_t *hf,
					off_t offset, off_t length,
					bsdsum_flag_t flags)
{
	struct stat st;
	struct stat *pst = &st;
	void *base;
	off_t len;
	int f;
	int r = 0;
	bsdsum_op_t *o;
	off_t total;

	DBG("digest_reg: %s %zi %zi\n", file, offset, length);
	if (stsrc)
		pst = stsrc;
	else if (stat(file, &st)) {
		bsdsum_log(LL_ERR, "cannot stat file %s", file);
		return RES_ERROR;
	}

	if ((pst->st_mode & S_IFMT) == S_IFBLK) {
		total = bsdsum_device_size(file); 
		if (total == (off_t)(-1)) {
			bsdsum_log(LL_ERR, 
				"block device not supported (%s)", file);
			return RES_ERROR;
		}
	}
	else
		total = pst->st_size;

	if (offset < 0) 
		offset = 0;
	else if (offset >= total) {
		bsdsum_log(LL_ERR, "bad offset specified");
		return RES_ERROR;
	}
	if (length < 0) 
		length = total - offset;
	else if (length > total) {
		bsdsum_log(LL_ERR, "bad length specified");
		return RES_ERROR;
	}
	if (offset + length > total) {
		bsdsum_log(LL_ERR, "bad offset/length specified");
		return RES_ERROR;
	}

	/* special case for length == 0 */
	if (length == 0) {
		unsigned char dummy = 0;
	
		for (o = hf; o; o = o->next) 
			r |= bsdsum_digest_mem(o, &dummy, 0, o->split);
		return(r);
	}

	/* non-empty area to hash, open the target */
	f = open(file, O_RDONLY);
	if (f < 0) {
		bsdsum_log(LL_ERR, "cannot open file %s", file);
		close(f);
		return RES_ERROR;
	}

	if ( ! (flags & FLAG_RAW))
	       	base = mmap(NULL, total, PROT_READ,
				MAP_PRIVATE, f, 0); 
	else
		base = (void*)(-1);

	if (base == (void*)(-1)) {  
		/* could not mmap, or FLAG_RAW, read it */
		close(f); 
		return bsdsum_digest_file(file, hf, offset, length);
	}

	/* apply algorithms */
	for (o = hf; o; o = o->next) {
		r |= bsdsum_digest_mem(o, base + offset, 
					length, o->split);
	}

	if (base)
		munmap(base, total);
	close(f);
	if (r) {
		bsdsum_log(LL_ERR, "could not digest file %s", file);
		return RES_ERROR;
	}

	return RES_OK;
}

/* Hash a link */
static bsdsum_res_t bsdsum_digest_lnk(int ofile,
					bsdsum_op_t *ops, 
					const char *file, 
					bsdsum_flag_t flags)
{
	char rlnk[PATH_MAX+1];

	if (readlink(file, rlnk, MAX_PATH) < 0) {
		bsdsum_log(LL_ERR, "could not read link %s", file);
		return RES_ERROR;
	}

	return bsdsum_digest_one(ofile, ops, rlnk,
				 flags, -1, -1);
}

static char rpath[PATH_MAX+1];

/* Recursive hashing of a directory. */
static bsdsum_res_t bsdsum_digest_dir(int ofile,
					bsdsum_op_t *ops, 
					const char *dir, 
					bsdsum_flag_t flags)
{
	DIR *d;
	struct dirent *dr;
	bsdsum_res_t res = RES_OK;
	bsdsum_res_t lres;

	d = opendir(dir);
	if (d == NULL) {
		bsdsum_log(LL_ERR, 
			"unable to access directory %s\n", dir);
		return RES_ERROR;
	}
	while(1) {
		lres = RES_OK;
		errno = 0;
		dr = readdir(d);
		if (dr == NULL) {
			closedir(d);
			if (errno != 0) {
				bsdsum_log(LL_ERR, 
				"directory access error (%s)\n", dir);
				return RES_ERROR;
			}
			return res;
		}
		if (dr->d_name[0] == '.') {
			if (dr->d_name[1] == '\0' ||
				(dr->d_name[1] == '.' &&
				 dr->d_name[2] == '\0'))
			 continue;
		}
		if (strlen(dir)+strlen(dr->d_name) >= MAX_PATH) {
			bsdsum_log(LL_ERR, 
				"too long path (%s, %s)", dir, dr->d_name);
			closedir(d);
			return RES_ERROR;
		}
		snprintf(rpath, MAX_PATH, "%s/%s", dir, dr->d_name); 
		lres = bsdsum_digest_one(ofile, ops, rpath, flags,
						-1, -1);
		if (lres & RES_ERROR)
			res = RES_ERROR;
	}
	return res;
}

/* Digest 'file' using algorithms 'ops' and output the results into file
 * 'ofile'. Returns RES_OK, RES_ERROR, RES_SKIPPED.
 */
bsdsum_res_t bsdsum_digest_one (int ofile, bsdsum_op_t* ops, 
				const char *file, bsdsum_flag_t flags,
				off_t offset, off_t length)
{
	bsdsum_op_t *hf;
	bsdsum_res_t res;
	size_t nread;
	int std = 0;
	int error;
	struct stat st;

	if (strcmp(file, "-") == 0)
		std = 1;

	/* process all data */
	if (std) {
		unsigned char data[BUFFER_STDIN_SZK*1024];

		for (hf = ops; hf; hf = hf->next) 
			bsdsum_digest_init(hf, -1);
		while ((nread = fread(data, 1UL, 
					BUFFER_STDIN_SZK*1024, stdin)) != 0) {
			if (flags & FLAG_P) {
				(void)fwrite(data, nread, 1UL, stdout);
				if (fflush(stdout) != 0) {
					bsdsum_log(LL_ERR,
						"stdout: write error");
					return RES_ERROR;
				}
			}
			for (hf = ops; hf; hf = hf->next) {
				hf->update(hf->ctx, 
					(unsigned char*)data, nread);
			}
		}
		for (hf = ops; hf; hf = hf->next) {
			if (bsdsum_digest_end(hf) != RES_OK)
				res = RES_ERROR;
		}
	}
	else {
		if (stat(file, &st)) {
			bsdsum_log(LL_ERR, 
				"unable to stat file %s\n", file);
			return RES_ERROR;
		}
		switch(st.st_mode & S_IFMT) {
		case S_IFREG:
			res = bsdsum_digest_reg(file, &st, ops, 
						offset, length, flags);
			if (res != RES_OK)
				return res;
			break;
		case S_IFDIR:
			if (flags & FLAG_R) 
				return bsdsum_digest_dir(ofile, ops, 
							file, flags);
			else {
				bsdsum_log(LL_WARN, 
					"skipping directory %s", file);
				return RES_SKIPPED;
			}
		case S_IFLNK:
			if (flags & FLAG_K)
				return RES_OK;
			else
				return bsdsum_digest_lnk(ofile, ops, 
							file, flags);
		case S_IFBLK:
			res = bsdsum_digest_reg(file, &st, ops, offset,
						length, flags | FLAG_RAW);
			if (res != RES_OK)
				return res;
			break;
		case S_IFCHR:
		case S_IFIFO:
		case S_IFSOCK:
			bsdsum_log(LL_WARN, 
				"skipping file %s (unsupported type)",
			       	file);
			return RES_SKIPPED;
		}
	}

	/* output the results */
	for (hf = ops; hf; hf = hf->next) {
		if (std)
			dprintf(ofile, "%s\n", hf->fdigest);
		else
			bsdsum_digest_print(ofile, hf, file);
	}
	return res;
}

