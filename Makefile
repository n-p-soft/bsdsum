# bsdsum
# (c) Nicolas Provost, 2022-2023 <dev AT npsoft DOT fr>
# License: BSD (see file COPYING)

.SUFFIXES: .o .c

all: out/bsdsum 


ARC := ChangeLog configure COPYING doc include external Makefile README.md
ARC += releases src tests TODO version

.PHONY: targz
targz: out/bsdsum
	@echo "building out/bsdsum-$(VER).tar.gz"; \
		rm -Rf out/bsdsum-$(VER); \
		mkdir -p out/bsdsum-$(VER); \
		cp -aR $(ARC) out/bsdsum-$(VER); \
		cd out; \
		find bsdsum-$(VER) -name '*.o' -delete; \
		tar cfz bsdsum-$(VER).tar.gz bsdsum-$(VER) || exit 1; \
		rm -Rf bsdsum-$(VER); \
		./bsdsum -a sha384 -s base64 -o bsdsum-$(VER).tar.gz.dg \
			bsdsum-$(VER).tar.gz; \
		cat bsdsum-$(VER).tar.gz.dg


include config.mk

OBJS := src/bsdsum_b64.o \
	src/bsdsum.o \
	src/bsdsum_op.o \
	src/bsdsum_test.o \
	src/bsdsum_sha3.o \
	src/bsdsum_size.o \
	src/bsdsum_help.o \
	src/bsdsum_tools.o \
	src/bsdsum_digest.o \
	src/bsdsum_dgl.o \
	src/bsdsum_enc.o \
	external/libcrypto/sha/sha256.o \
	external/libcrypto/sha/sha1dgst.o \
	external/libcrypto/sha/sha512.o \
	external/libcrypto/md5/md5_dgst.o \
	external/whirlpool/byte_order.o \
	external/whirlpool/whirlpool_sbox.o \
	external/whirlpool/whirlpool.o \
	external/blake/blake.o \
	external/blake2/blake2b-ref.o \
	external/blake2/blake2s-ref.o \
	external/blake3/blake3_dispatch.o \
	external/blake3/blake3_portable.o \
	external/blake3/blake3.o 

DEFS := -DVERSION=\"$(VER)\" -DOS_$(OS)

CFLAGS := $(C_FLAGS) $(DEFS)

DESTDIR ?= 

config.mk:
	@ ./configure || exit 1

static: out/bsdsum-static

src/bsdsum.o: src/bsdsum.c
	$(CC) -c -o $@ $(CFLAGS) $<

.c.o:
	$(CC) -c -o $@ $(CFLAGS) $(OPTS) $<

out/bsdsum: config.mk include/bsdsum.h $(OBJS)
	@mkdir -p out
	@$(CC) -o out/bsdsum $(CFLAGS) $(OBJS) && \
		echo "bsdsum compiled."	

out/bsdsum-static: config.mk $(OBJS)
	@mkdir -p out
	@$(CC) -static -o out/bsdsum-static $(CFLAGS) $(OBJS) && \
		echo "bsdsum-static compiled."	

.PHONY: install
install: out/bsdsum
	install -d ${DESTDIR}${PREFIX}/bin
	install out/bsdsum ${DESTDIR}${PREFIX}/bin
	#install -d ${DESTDIR}/usr/share/man/man1
	#install bsdsum.1 ${DESTDIR}/usr/share/man/man1

.PHONY: distclean
distclean: clean
	@rm -f config.mk

.PHONY: clean
clean:
	@rm -f out/bsdsum out/bsdsum-static $(OBJS)

.PHONY: check
check: out/bsdsum
	@$(MAKE) -C tests || exit 1

.PHONY:snap
snap:
	@cd ..; tar cfz /tmp/bsdsum.tar.gz bsdsum && \
		sha1sum /tmp/bsdsum.tar.gz > /tmp/bsdsum.tar.gz.sha1 && \
		cat /tmp/bsdsum.tar.gz.sha1

.PHONY: swapcheck
snapcheck:
	@sha1sum -c /tmp/bsdsum.tar.gz.sha1 && \
		tar -C .. -d -z -f /tmp/bsdsum.tar.gz || exit 1

