/* Minimal BOF fixture for loader tests. Test-only provenance: the compiled
 * object bytes are embedded in agent tests (see coff_test.go and
 * tasks_test.c); this source regenerates them and is never linked into the
 * agent (the builder skips *_test.c).
 *
 *   zig cc -target x86_64-windows-gnu -c fixture_bof_test.c -o fixture.o
 *
 * The entrypoint exercises the Beacon data + output API the loaders must
 * provide: BeaconDataParse/Int/Extract over the packed argument buffer and
 * BeaconPrintf with four format arguments (enough to spill past the four
 * register slots on x64, proving varargs forwarding works).
 */
int BeaconPrintf(int type, char *fmt, ...);

typedef struct {
    char *original;
    char *buffer;
    int length;
    int size;
} datap;

void BeaconDataParse(datap *parser, char *buffer, int size);
int BeaconDataInt(datap *parser);
char *BeaconDataExtract(datap *parser, int *size);

/* Real BOFs build without stack guards (references the loader cannot
 * resolve), so the fixture disables them explicitly. */
__attribute__((no_stack_protector)) void go(char *args, int alen) {
    datap p;
    int n, zlen = 0;
    char *z;
    BeaconDataParse(&p, args, alen);
    n = BeaconDataInt(&p);
    z = BeaconDataExtract(&p, &zlen);
    BeaconPrintf(0, "n=%d z=%s tail=%d %s", n, z, 7, "end");
}
