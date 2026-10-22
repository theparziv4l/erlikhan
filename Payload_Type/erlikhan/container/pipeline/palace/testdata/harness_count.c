/* Counting variant: the blob is built with PALACE_TEST_COUNT so
 * go() returns the mask-round count in EAX. */
#include <stdio.h>
#include <windows.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: harness_count blob.bin\n");
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        printf("open failed\n");
        return 2;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len <= 0 || len > 32 * 1024 * 1024) {
        printf("bad length %ld\n", len);
        return 2;
    }
    void *rx = VirtualAlloc(0, (SIZE_T)len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!rx) {
        printf("alloc failed\n");
        return 2;
    }
    if (fread(rx, 1, (size_t)len, f) != (size_t)len) {
        printf("read failed\n");
        return 2;
    }
    fclose(f);
    FlushInstructionCache(GetCurrentProcess(), rx, (SIZE_T)len);
    int n = ((int (*)(void))rx)();
    printf("ROUNDS=%d\n", n);
    return 0;
}
