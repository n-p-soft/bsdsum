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
 * The original Keccak reference code below is public-domain.
 */

#include <stdlib.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef OS_LINUX
#include <linux/fs.h>
#endif
#include "bsdsum.h"

void explicit_bzero(void* p, size_t sz)
{
	unsigned char* q = p;
	size_t i;

	if (q == NULL)
		return;
	for (i = 0; i < sz; i++)
		*q++ = 0;
}

/* get a device length. Return (off_t)(-1) on failure. */
off_t bsdsum_device_size(const char* dev)
{
#ifndef BSDSUM_LF
	/* large files support (or 64-bit cpu) needed */
	return (off_t)(-1);
#else
	int fd;
	off_t len;

	if (dev == NULL)
		return (off_t)(-1);
	fd = open(dev, O_RDONLY);
	if (fd < 0)
		return (off_t)(-1);
#ifdef OS_LINUX
	{
		uint64_t sz;

		if (ioctl(fd, BLKGETSIZE64, &sz))
			len = (off_t)(-1);
		else {
			len = (off_t)sz;
			if ((uint64_t)len != sz)
				len = (off_t)(-1);
		}
	}
#else
	len = lseek(fd, 0, SEEK_END);
	if (len <= 0)
		len = (off_t)(-1);
#endif /* OS_LINUX */
	close(fd);
	return len;
#endif /* BSDSUM_LF */
}

/* current log level */
bsdsum_ll_t bsdsum_log_level = LL_DEF;

/* additional log file */
int bsdsum_log_fd = -1;

/* our logging function */
void bsdsum_log(bsdsum_ll_t lvl, const char *fmt, ...)
{
	char buf[1310];
	va_list va;
	size_t len;

	if (fmt == NULL)
		return;

	if ( ! (lvl & bsdsum_log_level))
		return;

	va_start(va, fmt);
	vsnprintf(buf, 1300, fmt, va);
	if (fmt[strlen(fmt)-1] != '\n') {
		buf[strlen(buf)+1] = 0;
		buf[strlen(buf)] = '\n';
	}
	va_end(va);
	if (bsdsum_log_fd > 0)
		dprintf(bsdsum_log_fd, "%s", buf);
	if (lvl & LL_STDOUT)
		fprintf(stdout, "%s", buf, strlen(buf));
	else
		fprintf(stderr, "bsdsum: %s", buf);
	if (lvl & LL_FATAL)
		exit(1);
}

/* dynamic concat */
char *bsdsum_concat(const char *a, const char *b)
{
	char *s;

	if (a == NULL) {
		if (b == NULL)
			return NULL;
		else
			s = strdup(b);
	}
	else if (b == NULL)
		s = strdup(a);
	else {
		size_t lena = strlen(a);
		size_t lenb = strlen(b);

		s = malloc(lena + lenb + 1);
		if (s)
			snprintf(s, lena + lenb + 1, "%s%s", a ,b);
		else
			bsdsum_log(LL_ERR|LL_FATAL, "out of memory");
	}
	return s;
}

