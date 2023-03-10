bsdsum
======

Last modified: 2023/01/31.

  bsdsum is a tool for computing and checking digests of data. It runs under
GNU/Linux and BSD systems. Its name comes from the fact it is BSD-licensed and
derived from the BSD 'cksum' program. The tool supports the following digests
formats:

  - BSD format: "ALG (FILE) = DIGEST_HEX_ENCODED", or,
                "ALG (FILE) = DIGEST_BASE64_ENCODED", and/or
                "SIZE (FILE) = size_of_file"

  - GNU coreutils format: "DIGEST  FILE" (only md5, sha1, sha2)

  - cksum variant: "DIGEST FILE" (one space, only md5, sha1, sha2)

  The style of output is specified with the "-s" option:

    -s default: for BSD format (default style if unspecified)
    -s base64: for BSD base64-encoded format
    -s mix32: BSD format using a custom character set including 32 punctuation
              signs, letters, digits
    -s gnu: for GNU coreutils output
    -s cksum: for cksum variant
    -s terse: output the raw hexadecimal result without the file name
    -s binary: output the raw binary digest

  Supported algorithms are:

   MD5, SHA1, SHA256 (default choice if not specified), SHA384, SHA512,
   Keccak-1600 SHA3-256 and SHA3-512,
   WHIRLPOOL (512 bits),
   BLAKE224, BLAKE256, BLAKE384, BLAKE512,
   BLAKE2B (512 bits, unkeyed), BLAKE2S (256 bits, unkeyed),
   BLAKE3 (256 bits, unkeyed),
   SIZE (output the length of the file). 

  Multiple algorithms may be specified for each source of data, using the -a 
option (i.e. -a md5,sha1,size).

  On Linux (both 32-bit and 64-bit) and 64-bit BSDs, large files support is
available, else the maximum length of the files is 2 or 4 GB and block devices
are not supported.


Split digests
=============

  In addition, a special "split" mode can be used to compute digests of files
only (not data sent thru stdin). The split mode is enabled using "-a ALG:N",
where ALG is one of:

  MD5, SHAxxx, SHA3-xxx, WHIRLPOOL, BLAKExxx

  and N an integer greater or equal than 2. 

  Each source file is split into N equal parts and each part is hashed in a 
separate thread to produce the digest D(i). Once the digests D(i) i=1..N are 
computed, they are concatenated and the final digest is the hash of this data:
ALG(D(1)|...|D(N)). This let you use all the cpus of your machine; with two 
cpus, SHA256:2 is two times faster than SHA256.

  *note* that the digests produced using ALG and ALG:N are NOT the same.


Usage
=====

  - read the embedded help:

        bsdsum -h

  - compute and display the SHA256 digest of file 'data':

        bsdsum -a sha256 data

    or

        cat data | bsdsum -a sha256

  - store the SHA256:2 split digest of file 'data' into 'data.dg'
    (the 'cat' method above will not work for split digests, as
    the length of the input data must be known):

        bsdsum -a sha256:2 -o data.dg data

    or

        bsdsum -a sha256:2 data > data.dg

  - fully check the digests stored in the file 'data.dg' (multiple lists to
    check can be specified on the command-line):

        bsdsum -c data.dg

  - fully check the list of digests read from standard input:

        bsdsum -c

  - check the digest for file 'my_file' from the list of digests 'data.dg'
    (only one list of files to check can be specified when using -C):

        bsdsum -C data.dg my_file

    Note: for such a query, an error is reported if 'my_file' is not found in
          the list 'data.dg'.

  - check the MD5 digest (only) for file 'my_file' from the list of digests
    'data.dg':

        bsdsum -C data.dg -a md5 my_file

  - store the SHA3-256 digest, base64-encoded and the length of file 'data'
    into 'data.dg':

        bsdsum -s base64 -a sha3-256,size data > data.dg

  - compute the SHA-256 digest of the data in file './data' from offset 100
    to 149 (only one file to digest must be specified here, and the output
    is always done in "terse" style):

        bsdsum -f 100 -l 50 ./data

  - hash any file under directory ./src/ (recursively), but skipping links:

        bsdsum -r -k ./src

  - run the tiny auto-test:

        bsdsum -t


Build & install
===============

* tested systems: GNU/Linux, FreeBSD, OpenBSD, NetBSD, DragonFlyBSD, using
  either gcc or clang C compiler

* dependencies: libc only

* first run the "./configure" script. Then, on success, run "make" to build
  the binary out/bsdsum and run some tests. You can also run "make static"
  to produce the static binary "out/bsdsum-static" that has no dependency.

* you should now run "make check" to launch the tiny test suite

* install the files using "make install" (under root user). You can add
  DESTDIR=xxx to install files under the directory xxx/ (by default, equal to
  the prefix setup by the configure script).

* configure script options:
  --prefix=...   specify installation/configuration prefix (default /usr/local)
  --cc=...   to specify the name of the C compiler (gcc, clang, default: auto)

* other make targets:
  make static: build out/bsdsum-static (static binary)
  make clean: clean building tree, keeping configuration
  make distclean: clear all generated files
  make check: run the tests


Lists of digests
================

  A list of digests is a file (as produced using the -o option) that stores
hashes for many other files. Such a file may be specified when using the
-c/-C options to verify a list of digests. Valid lines are:

  - empty ones (ignored),

  - lines starting with # (comments, ignored)

  - "ALG(FILE) = DIGEST"

  - "DIGEST  FILE" (two spaces)

  - "DIGEST FILE" (one space)

  - "# $BSDSUM: date,digest $" as last line of the file, stores the "supersum"
    of the list, that is, the digest of all valid lines (except ignored ones)
    above itself.

  Any other line will be rejected and an error reported.


