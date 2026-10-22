// Package palace reimplements the Crystal Palace Kit linker (PalaceKit)
// as a native Go pipeline stage: it parses AMD64 COFF objects, merges
// them into one position-independent blob, evaluates the Crystal Kit
// spec DSL, and embeds the XOR-masked shellcode as named RESOURCE
// sections. No Java, no crystalpalace.jar.
package palace

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// ROR13 hashes an API name exactly like the loader's patch_resolve:
// rotate right 13 bits, then add the next byte.
func ROR13(name string) uint32 {
	var h uint32
	for i := 0; i < len(name); i++ {
		h = (h >> 13) | (h << 19) + uint32(name[i])
	}
	return h
}

// APINames is every function the loader resolves at runtime. The C
// header services.h carries the same list as H_<name> constants;
// CheckServiceHeader proves the two agree.
var APINames = []string{
	"NtAllocateVirtualMemory",
	"NtWriteVirtualMemory",
	"NtProtectVirtualMemory",
	"NtCreateThreadEx",
	"NtWaitForSingleObject",
	"NtFreeVirtualMemory",
	"NtOpenProcess",
	"RtlExitUserThread",
	"VirtualAlloc",
	"VirtualProtect",
	"VirtualFree",
	"LoadLibraryA",
	"LoadLibraryW",
	"GetProcAddress",
	"ExitThread",
	"CreateToolhelp32Snapshot",
	"Process32FirstW",
	"Process32NextW",
	"OpenProcess",
	"CreateProcessW",
	"CloseHandle",
	"SetProcessValidCallTargets",
	"NtSuspendThread",
	"NtResumeThread",
	"OpenThread",
	"Thread32First",
	"Thread32Next",
	"ResumeThread",
	"NtDelayExecution",
}

// Hashes returns the ROR13 hash of every API name.
func Hashes() map[string]uint32 {
	out := make(map[string]uint32, len(APINames))
	for _, n := range APINames {
		out[n] = ROR13(n)
	}
	return out
}

// GenHashes prints the hash table (the gen-hashes tooling).
func GenHashes() string {
	var b strings.Builder
	for _, n := range APINames {
		fmt.Fprintf(&b, "%-32s 0x%08X\n", n, ROR13(n))
	}
	return b.String()
}

var hashDefineRe = regexp.MustCompile(`(?m)^\s*#define\s+H_([A-Za-z0-9_]+)\s+0x([0-9A-Fa-f]+)`)

// CheckServiceHeader parses #define H_<name> 0xHASH lines from a C
// header and recomputes each hash independently. Any mismatch fails
// the build: a wrong constant means patch_resolve returns NULL and
// the loader crashes on the target.
func CheckServiceHeader(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	found := map[string]bool{}
	var bad []string
	for _, m := range hashDefineRe.FindAllStringSubmatch(string(raw), -1) {
		name, want := m[1], strings.ToUpper(m[2])
		found[name] = true
		if got := fmt.Sprintf("%08X", ROR13(name)); got != want {
			bad = append(bad, fmt.Sprintf("H_%s: header 0x%s, want 0x%s", name, want, got))
		}
	}
	if len(found) == 0 {
		return fmt.Errorf("no H_* defines in %s", path)
	}
	var missing []string
	for _, n := range APINames {
		if !found[n] {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("header %s misses %d API hashes: %s", path, len(missing), strings.Join(missing, ", "))
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("stale ROR13 hashes in %s:\n%s", path, strings.Join(bad, "\n"))
	}
	// Reject unknown extras too: a typo'd name would never match.
	known := map[string]bool{}
	for _, n := range APINames {
		known[n] = true
	}
	var extra []string
	for name := range found {
		if !known[name] {
			extra = append(extra, name)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("unknown H_* defines in %s: %s", path, strings.Join(extra, ", "))
	}
	return nil
}
