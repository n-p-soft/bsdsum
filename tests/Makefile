PRG=../out/bsdsum

.PHONY: all 
all: 
	@$(PRG) -t || exit 1
	@echo "* FILELIST1"; $(PRG) -v nothing -c sums || exit 1
	@echo "* FILELIST2"; $(PRG) -v nothing -c sums0 || exit 1
	@echo "* FILELIST3"; $(PRG) -v nothing -C sums a || exit 1
	@echo "* SUBDIR"; $(PRG) -r sub > /tmp/bsdst; \
		diff /tmp/bsdst sumsub || exit 1
	@echo "* LENGTH0"; A=$$(cat z5); \
		B=$$($(PRG) -a md5 -l 0 a); \
		test "-$${A}-" = "-$${B}-" || exit 1
	@echo "* LENGTH1"; A=$$(cat l1); \
		B=$$($(PRG) -a sha1 -l 1 -f 0 a); \
		test "-$${A}-" = "-$${B}-" || exit 1
	@echo "* OFFSET"; A=$$(cat l1); \
		B=$$($(PRG) -a sha1 -f 1 e); \
		test "-$${A}-" = "-$${B}-" || exit 1
	@echo "* LNKK"; A=$$(cat lnk2); \
		B=$$($(PRG) -a md5 -k -r lnk); \
		test "-$${A}-" = "-$${B}-" || exit 1
	@echo "* CMDC2"; \
		B=$$($(PRG) -v verbose -c sums sums0 1>/dev/null 2>/tmp/bsdst); \
		C="bsdsum: count of items: 16"; \
		A=$$(grep "$$C" /tmp/bsdst); \
		test "-$${A}-" = "-$${C}-" || exit 1
	@echo "* CSEL2"; $(PRG) -v verbose -v file=/tmp/bsdst \
	      	-C sums a z 1>/dev/null 2>/dev/null; \
		A=$$(grep "z was not found nor checked" /tmp/bsdst); \
		test -n "$${A}" || exit 1
	@echo "* CSTDIN"; cat sums | $(PRG) -c -v nothing; \
		exit $$?
	@echo "* CPREPEND"; \
		A=$$($(PRG) -d sub -c sumsubpr > /tmp/bsdst); \
		B=$$(grep OK /tmp/bsdst | wc -l); \
		test "$$B" = "2" || exit 1
	@echo "* HPREPEND"; \
		A=$$($(PRG) -d sub a 2>/dev/null); \
	        test "$$A" = "$$(cat sumsubpr2)" || exit 1	



