# bsdsum
# (c) Nicolas Provost, 2022-2023 <dev AT npsoft DOT fr>
# License: BSD (see file COPYING)
# Version 1.0 20220302
# Version 1.1 20221210
# Version 1.2 20221217
# Version 1.3 20221218
# Version 1.4 01/2023

include config.mk

OBJS := src/base64.o src/bsdsum.o src/test.o \
	src/sha3.o src/size.o \
	libcrypto/sha/sha256.o \
	libcrypto/sha/sha1dgst.o \
	libcrypto/sha/sha512.o \
	libcrypto/md5/md5_dgst.o

DEFS := -DVERSION=\"$(VER)\" -DOS_$(OS)

CFLAGS := $(C_FLAGS) $(DEFS)

DESTDIR ?= 

.SUFFIXES: .o .c

all: out/bsdsum 

static: out/bsdsum-static

src/bsdsum.o: src/bsdsum.c
	$(CC) -c -o $@ $(CFLAGS) $<

.c.o:
	$(CC) -c -o $@ $(CFLAGS) $(OPTS) $<

out/bsdsum: $(OBJS)
	@mkdir -p out
	@$(CC) -o out/bsdsum $(CFLAGS) $(OBJS) && \
		echo "bsdsum compiled."	

out/bsdsum-static: $(OBJS)
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
	@out/bsdsum -t || exit 1
	@echo "FILELIST1"; cd tests; ../out/bsdsum -c sums || exit 1
	@echo "FILELIST2"; cd tests; ../out/bsdsum -c sums0 || exit 1

.PHONY: targz
targz: distclean
	@F=$$(pwd); cd ..; \
		tar cfz bsdsum-$(VER).tar.gz $$(basename $$F) || exit 1; 

