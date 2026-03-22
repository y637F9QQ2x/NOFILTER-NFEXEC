# NOFILTER-NFEXEC — Unified Makefile
#
# Prerequisites (Debian / Ubuntu):
#   apt install gcc-mingw-w64-x86-64

CC_X64  = x86_64-w64-mingw32-gcc
CFLAGS  = -c -w

OUT_DIR = bin
NF_OBJ  = $(OUT_DIR)/nofilter.x64.o
NX_OBJ  = $(OUT_DIR)/nfexec.x64.o

.PHONY: all clean verify

all: $(NF_OBJ) $(NX_OBJ) verify

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(NF_OBJ): nofilter.c beacon.h nofilter.syms | $(OUT_DIR)
	@cp nofilter.c _nf.c
	$(CC_X64) $(CFLAGS) _nf.c -o $(NF_OBJ)
	@rm -f _nf.c
	@x86_64-w64-mingw32-objcopy --redefine-sym _nf.c=_b --redefine-syms nofilter.syms $(NF_OBJ) 2>/dev/null || true

$(NX_OBJ): nfexec.c beacon.h PowershellRunner.h nfexec.syms | $(OUT_DIR)
	@cp nfexec.c _nx.c
	$(CC_X64) $(CFLAGS) _nx.c -o $(NX_OBJ)
	@rm -f _nx.c
	@x86_64-w64-mingw32-objcopy --redefine-sym _nx.c=_b --redefine-syms nfexec.syms $(NX_OBJ) 2>/dev/null || true

verify: $(NF_OBJ) $(NX_OBJ)
	@echo ""
	@echo "=== Build Verification ==="
	@for obj in $(NF_OBJ) $(NX_OBJ); do \
		echo ""; \
		echo "--- $$obj ---"; \
		file $$obj; \
		objdump -t $$obj | grep " go$$" || echo "[!] 'go' not found"; \
		echo "  .bss: $$(objdump -h $$obj | grep '\.bss' | awk '{print $$3}')"; \
		echo "  OPSEC strings: $$(strings $$obj | grep -ciE '^amsi|^etw|nfexec|nofilter')"; \
		echo "  OPSEC symbols: $$(objdump -t $$obj | grep -v '__imp_' | grep -ciE 'peb|ssn|gadget|veh|setup|hwbp|syscall|powershell|runner|extract|amsi|etw|handle|token|proc|ioctl|enc|svc')"; \
	done
	@echo ""
	@echo "=== Done ==="

clean:
	rm -rf $(OUT_DIR)
