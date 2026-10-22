package palace

import (
	"encoding/binary"
	"testing"
)

// ROR13 vectors from an independent Python implementation; the
// NtVirtual set also matches the Crystal Palace documentation's
// gen-hashes output.
func TestROR13Vectors(t *testing.T) {
	vectors := map[string]uint32{
		"NtAllocateVirtualMemory":    0xD33BCABD,
		"NtWriteVirtualMemory":       0xC5108CC2,
		"NtProtectVirtualMemory":     0x8C394D89,
		"NtCreateThreadEx":           0x4D1DEB74,
		"NtWaitForSingleObject":      0xAE06C1B2,
		"NtFreeVirtualMemory":        0xDB63B5AB,
		"NtOpenProcess":              0xF0CA9CA0,
		"RtlExitUserThread":          0xFF7F061A,
		"VirtualAlloc":               0x91AFCA54,
		"VirtualProtect":             0x7946C61B,
		"VirtualFree":                0x030633AC,
		"LoadLibraryA":               0xEC0E4E8E,
		"LoadLibraryW":               0xEC0E4EA4,
		"GetProcAddress":             0x7C0DFCAA,
		"ExitThread":                 0x60E0CEEF,
		"CreateToolhelp32Snapshot":   0xE454DFED,
		"Process32FirstW":            0xD53992A4,
		"Process32NextW":             0x2A523C0A,
		"OpenProcess":                0xEFE297C0,
		"CreateProcessW":             0x16B3FE88,
		"CloseHandle":                0x0FFD97FB,
		"SetProcessValidCallTargets": 0x263109F2,
		"NtSuspendThread":            0x488D64DC,
		"NtResumeThread":             0xC54A46C8,
		"OpenThread":                 0x58C91E6F,
		"Thread32First":              0xB83BB6EA,
		"Thread32Next":               0x86FED608,
		"ResumeThread":               0x9E4A3F88,
		"NtDelayExecution":           0xD4F11852,
	}
	if len(vectors) != len(APINames) {
		t.Fatalf("vector count %d != API count %d", len(vectors), len(APINames))
	}
	for name, want := range vectors {
		if got := ROR13(name); got != want {
			t.Errorf("ROR13(%s) = %#08x, want %#08x", name, got, want)
		}
	}
}

func TestCheckServiceHeader(t *testing.T) {
	good := "#define H_NtAllocateVirtualMemory 0xD33BCABD\n"
	for _, n := range APINames {
		if n == "NtAllocateVirtualMemory" {
			continue
		}
		good += "#define H_" + n + " 0x" + hex8(ROR13(n)) + "\n"
	}
	path := writeTemp(t, "services.h", good)
	if err := CheckServiceHeader(path); err != nil {
		t.Fatalf("good header rejected: %v", err)
	}
	bad := writeTemp(t, "bad.h", "#define H_NtAllocateVirtualMemory 0xDEADBEEF\n"+good[len("#define H_NtAllocateVirtualMemory 0xD33BCABD\n"):])
	if err := CheckServiceHeader(bad); err == nil {
		t.Fatal("stale hash accepted")
	}
	missing := writeTemp(t, "missing.h", "#define H_NtAllocateVirtualMemory 0xD33BCABD\n")
	if err := CheckServiceHeader(missing); err == nil {
		t.Fatal("incomplete header accepted")
	}
	extra := writeTemp(t, "extra.h", good+"#define H_TypoFunc 0x12345678\n")
	if err := CheckServiceHeader(extra); err == nil {
		t.Fatal("unknown define accepted")
	}
}

func hex8(v uint32) string {
	const digits = "0123456789ABCDEF"
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = digits[v&0xF]
		v >>= 4
	}
	return string(b[:])
}

func TestPICOStubShape(t *testing.T) {
	stub := BuildPICOStub()
	if len(stub) != 8+16+2 {
		t.Fatalf("stub len %d", len(stub))
	}
	if total := binary.LittleEndian.Uint32(stub[0:4]); total != uint32(len(stub)) {
		t.Fatalf("total_size %d != %d", total, len(stub))
	}
	if n := binary.LittleEndian.Uint32(stub[4:8]); n != 2 {
		t.Fatalf("num_exports %d", n)
	}
	if stub[len(stub)-2] != 0xC3 || stub[len(stub)-1] != 0xC3 {
		t.Fatal("stub code is not RET RET")
	}
}

func TestXORRoundtrip(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	key := []byte{0xAA, 0xBB}
	enc := XORBytes(data, key)
	if string(enc) == string(data) {
		t.Fatal("no-op xor")
	}
	if string(XORBytes(enc, key)) != string(data) {
		t.Fatal("xor is not self-inverse")
	}
	r := PrependLen(data)
	if len(r) != 9 || binary.LittleEndian.Uint32(r[:4]) != 5 {
		t.Fatalf("bad RESOURCE header: %x", r[:4])
	}
}
