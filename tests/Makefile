PRG=../out/bsdsum

.PHONY: all 
all: 
	@$(PRG) -t || exit 1
	@echo "* FILELIST1"; $(PRG) -c sums || exit 1
	@echo "* FILELIST2"; $(PRG) -c sums0 || exit 1
	@echo "* FILELIST3"; $(PRG) -C sums a || exit 1
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

