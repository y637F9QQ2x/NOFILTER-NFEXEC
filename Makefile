# NFEXEC - Makefile
#
# Prerequisites (Debian / Ubuntu):
#   apt install gcc-mingw-w64-x86-64

CC_X64  = x86_64-w64-mingw32-gcc
CFLAGS  = -c -w

SRC     = nfexec.c
OUT_DIR = bin
OUT_X64 = $(OUT_DIR)/nfexec.x64.o

.PHONY: all clean verify

all: $(OUT_X64) verify

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(OUT_X64): $(SRC) beacon.h PowershellRunner.h syms.map | $(OUT_DIR)
	@cp $(SRC) _t.c
	$(CC_X64) $(CFLAGS) _t.c -o $(OUT_X64)
	@rm -f _t.c
	@x86_64-w64-mingw32-objcopy --redefine-sym _t.c=_b --redefine-syms syms.map $(OUT_X64) 2>/dev/null || true

verify: $(OUT_X64)
	@echo ""
	@echo "=== Build Verification ==="
	@file $(OUT_X64)
	@echo ""
	@objdump -t $(OUT_X64) | grep " go$$" || echo "[!] 'go' symbol not found"
	@echo ""
	@echo "--- .bss ---"
	@objdump -h $(OUT_X64) | grep '\.bss' | awk '{print "  size: " $$3}'
	@echo ""
	@echo "--- Beacon symbols ---"
	@objdump -t $(OUT_X64) | grep '__imp_Beacon' | sed 's/.*__imp_/  __imp_/'
	@echo ""
	@echo "--- OPSEC strings ---"
	@strings $(OUT_X64) | grep -iE 'amsi|etw|nfexec' || echo "  [OK] Clean"
	@echo ""
	@echo "--- OPSEC symbols (should be empty) ---"
	@objdump -t $(OUT_X64) | grep -iE 'Peb|Ssn|Gadget|Veh|Setup|Hwbp|Syscall|Powershell|Runner|Extract' | grep -v '__imp_\|\.rdata' || echo "  [OK] All sanitized"
	@echo ""
	@echo "=== Done ==="

clean:
	rm -rf $(OUT_DIR)
