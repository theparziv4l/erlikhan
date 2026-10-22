package palace

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefines(t *testing.T) {
	o := Options{PICO: "stub", Inject: "self"}
	d, err := o.Defines()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(d, " ")
	for _, want := range []string{"-DWIN_X64", "-DPALACE_NO_ROR13", "-DPALACE_RWX", "-DPALACE_NO_XOR"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s in %s", want, joined)
		}
	}
	o = Options{
		PICO: "none", Inject: "host", Hosts: "a.exe,b.exe",
		ROR13: true, NoRWX: true, CFG: true, Cleanup: true,
		Hooks: true, SleepMask: true, Spoof: true, XOR: true,
	}
	d, err = o.Defines()
	if err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(d, " ")
	for _, want := range []string{
		"-DPALACE_ROR13", "-DPALACE_NO_RWX", "-DPALACE_CFG", "-DPALACE_CLEANUP",
		"-DPALACE_XOR", "-DPALACE_PICO_NONE", "-DPALACE_HOOKS", "-DPALACE_SLEEPMASK", "-DPALACE_SPOOF",
		"-DPALACE_INJECT_HOST", `-DPALACE_HOSTS="a.exe,b.exe"`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s in %s", want, joined)
		}
	}
	if _, err := (Options{Inject: "bogus"}).Defines(); err == nil {
		t.Error("bad inject accepted")
	}
	if _, err := (Options{Inject: "self", Hosts: `a";rm`}).Defines(); err == nil {
		t.Error("host injection characters accepted")
	}
}

func TestBuildWithFixture(t *testing.T) {
	dir := t.TempDir()
	shellcode := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01}
	if err := os.WriteFile(filepath.Join(dir, "loader.x64.o"), loaderFixture(), 0o644); err != nil {
		t.Fatal(err)
	}
	o := Options{Shellcode: shellcode, ObjDir: dir, MaskLen: 64, XOR: true, PICO: "stub"}
	out, err := o.Build()
	if err != nil {
		t.Fatal(err)
	}
	// code 16 + rdata 8 + data 4 + dll(4+5) + mask(4+64) + pico(26).
	if len(out) != 16+8+4+9+68+26 {
		t.Fatalf("len %d", len(out))
	}
	dllOff := 28
	if binary.LittleEndian.Uint32(out[dllOff:dllOff+4]) != uint32(len(shellcode)) {
		t.Fatal("dll header wrong")
	}
	maskOff := dllOff + 9
	mask := out[maskOff+4 : maskOff+4+64]
	if dec := XORBytes(out[dllOff+4:dllOff+9], mask); string(dec) != string(shellcode) {
		t.Fatal("shellcode does not roundtrip")
	}
	// XOR off stores the shellcode in the clear.
	o.XOR = false
	out, err = o.Build()
	if err != nil {
		t.Fatal(err)
	}
	if string(out[dllOff+4:dllOff+9]) != string(shellcode) {
		t.Fatal("xor=false should store plaintext")
	}
	// PICO off links an empty pico section.
	o.PICO = "none"
	out, err = o.Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 16+8+4+9+68 {
		t.Fatalf("pico=none len %d", len(out))
	}
}

func TestBuildRejects(t *testing.T) {
	dir := t.TempDir()
	if _, err := (Options{ObjDir: dir, MaskLen: 8}).Build(); err == nil {
		t.Error("short mask accepted")
	}
	if _, err := (Options{ObjDir: dir, MaskLen: 128, PICO: "full"}).Build(); err == nil {
		t.Error("bad pico accepted")
	}
	o := Options{ObjDir: dir, MaskLen: 128, PICO: "stub", SpecPath: filepath.Join(dir, "nope.spec")}
	if _, err := o.Build(); err == nil {
		t.Error("missing custom spec accepted")
	}
}
