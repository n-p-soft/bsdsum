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
 */

#include "bsdsum.h"

void bsdsum_help (void)
{
	fprintf(stderr, 
	"usage: bsdsum v" VERSION " - compute and check digests\n"
	"        [-h] show this help.\n"
	"        [-t] only run a simple auto-test.\n"
	"        [-p] echoes stdin to stdout and appends checksum\n"
	"             to stdout.\n"
        "        [-s STYLE] output format, one of:\n"
	"             default: \"ALG (FILE) = RESULT\"\n"
	"             base64: \"ALG (FILE) = BASE64_RESULT\"\n"
	"             sym64: \"ALG (FILE) = BASE64_SYM_RESULT\"\n"
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
	"             'WHIRLPOOL' compute WHIRLPOOL-512 digest\n"
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
	"             -s terse.\n"
	"        [-f] optional offset where to start when one, and\n"
	"             only one file to digest is specified. Implies\n"
	"             -s terse.\n"
	"        [-c] 'file' is a checklist.\n"
	"        [-C checklist] bsdsum_compare the checksum of 'file' against\n"
	"                       checksums in 'checklist'.\n"
	"        [-o hashfile] place the checksum into this file\n"
	"                      instead of stdout.\n"
	"        [file ...]\n");
}
