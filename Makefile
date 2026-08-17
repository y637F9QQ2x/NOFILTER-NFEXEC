# NOFILTER-NFEXEC — Unified Makefile
#
# Prerequisites (Debian / Ubuntu):
#   apt install gcc-mingw-w64-x86-64
#
# Layout:
#   src/   C sources, headers, objcopy symbol maps
#   bin/   build output (git-ignored; havoc/*.py load the objects from here,
#          so this directory name is part of the installed interface)
#
# Why the temp-file copy step:
#   The COFF symbol table records the translation unit path exactly as it was
#   handed to the compiler. Compiling src/nofilter.c directly would record the
#   string "src/nofilter.c", and the --redefine-sym below would silently miss.
#   The temp copy therefore stays in the repository root and must keep the short
#   name that --redefine-sym refers to. -I$(SRC_DIR) lets it find its headers.

CC_X64  = x86_64-w64-mingw32-gcc
OBJCOPY = x86_64-w64-mingw32-objcopy
OBJDUMP = objdump

SRC_DIR = src
OUT_DIR = bin
CFLAGS  = -c -w -I$(SRC_DIR)

NF_OBJ = $(OUT_DIR)/nofilter.x64.o
NX_OBJ = $(OUT_DIR)/nfexec.x64.o
OBJS   = $(NF_OBJ) $(NX_OBJ)

NF_TMP = _nf.c
NX_TMP = _nx.c

.PHONY: all clean verify
.DELETE_ON_ERROR:

all: verify

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(NF_OBJ): $(SRC_DIR)/nofilter.c $(SRC_DIR)/beacon.h $(SRC_DIR)/nofilter.syms | $(OUT_DIR)
	@set -e; trap 'rm -f $(NF_TMP)' EXIT INT TERM; \
	 echo "  CC       $@"; \
	 cp $(SRC_DIR)/nofilter.c $(NF_TMP); \
	 $(CC_X64) $(CFLAGS) $(NF_TMP) -o $@; \
	 echo "  OBJCOPY  $@"; \
	 $(OBJCOPY) --redefine-sym $(NF_TMP)=_b --redefine-syms $(SRC_DIR)/nofilter.syms $@

$(NX_OBJ): $(SRC_DIR)/nfexec.c $(SRC_DIR)/beacon.h $(SRC_DIR)/PowershellRunner.h $(SRC_DIR)/nfexec.syms | $(OUT_DIR)
	@set -e; trap 'rm -f $(NX_TMP)' EXIT INT TERM; \
	 echo "  CC       $@"; \
	 cp $(SRC_DIR)/nfexec.c $(NX_TMP); \
	 $(CC_X64) $(CFLAGS) $(NX_TMP) -o $@; \
	 echo "  OBJCOPY  $@"; \
	 $(OBJCOPY) --redefine-sym $(NX_TMP)=_b --redefine-syms $(SRC_DIR)/nfexec.syms $@

# Every check is an assertion: a regression fails the build instead of scrolling
# past in the log.
verify: $(OBJS)
	@echo ""; echo "=== Build Verification ==="; \
	 rc=0; \
	 for obj in $(OBJS); do \
	   echo ""; echo "--- $$obj ---"; \
	   if file $$obj | grep -q "x86-64 COFF object file"; then \
	     echo "  [ok]   x86-64 COFF object"; \
	   else echo "  [FAIL] not an x86-64 COFF object"; rc=1; fi; \
	   if $(OBJDUMP) -t $$obj | grep -q " go$$"; then \
	     echo "  [ok]   go() entry point exported"; \
	   else echo "  [FAIL] go() entry point missing -- CoffeeLdr cannot call it"; rc=1; fi; \
	   bss=$$($(OBJDUMP) -h $$obj | grep '\.bss' | awk '{print $$3}'); \
	   if [ -z "$$bss" ] || [ "$$bss" = "00000000" ]; then \
	     echo "  [ok]   .bss empty"; \
	   else echo "  [FAIL] .bss is $$bss -- globals must land in .data"; rc=1; fi; \
	   n=$$(strings $$obj | grep -ciE '^amsi|^etw|nfexec|nofilter'); \
	   if [ "$$n" -eq 0 ]; then echo "  [ok]   no plaintext OPSEC strings"; \
	   else echo "  [FAIL] $$n plaintext OPSEC strings"; rc=1; fi; \
	   n=$$($(OBJDUMP) -t $$obj | grep -v '__imp_' | grep -ciE 'peb|ssn|gadget|veh|setup|hwbp|syscall|powershell|runner|extract|amsi|etw|handle|token|proc|ioctl|enc|svc'); \
	   if [ "$$n" -eq 0 ]; then echo "  [ok]   no OPSEC symbol names"; \
	   else echo "  [FAIL] $$n OPSEC symbol names survived objcopy"; rc=1; fi; \
	   n=$$($(OBJDUMP) -t $$obj | grep -c 'BeaconFormat'); \
	   if [ "$$n" -eq 0 ]; then echo "  [ok]   no BeaconFormat* references"; \
	   else echo "  [FAIL] $$n BeaconFormat* references"; rc=1; fi; \
	 done; \
	 echo ""; \
	 if [ $$rc -ne 0 ]; then echo "=== FAILED ==="; exit 1; fi; \
	 echo "=== All checks passed ==="

clean:
	rm -rf $(OUT_DIR) $(NF_TMP) $(NX_TMP)
