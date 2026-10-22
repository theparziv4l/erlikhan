/* Unity build: a single translation unit, so MinGW emits no
 * .refptr/ADDR64 cross-TU global indirection (absolute addresses
 * cannot work in PIC shellcode). */
#include "services.c"
#include "pico.c"
#include "hooks.c"
#include "mask.c"
#include "spoof.c"
#include "cfg.c"
#include "cleanup.c"
#include "loader.c"
