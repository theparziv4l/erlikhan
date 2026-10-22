package palace

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func needMingw(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("x86_64-w64-mingw32-gcc"); err != nil {
		t.Skip("mingw cross compiler needed")
	}
}

// linkReal compiles the unity loader and links shellcode through the
// default spec, returning the blob and object dir.
func linkReal(t *testing.T, shellcode []byte, mutate func(*Options)) ([]byte, Options) {
	t.Helper()
	needMingw(t)
	objDir := t.TempDir()
	o := Options{
		Shellcode: shellcode,
		SrcDir:    "src",
		ObjDir:    objDir,
		MaskLen:   128,
		XOR:       true,
		PICO:      "stub",
		ROR13:     true,
		NoRWX:     true,
		Cleanup:   true,
		Inject:    "self",
	}
	if mutate != nil {
		mutate(&o)
	}
	if err := o.Compile(); err != nil {
		t.Fatal(err)
	}
	out, err := o.Build()
	if err != nil {
		t.Fatal(err)
	}
	return out, o
}

// TestLinkRealObject proves the production unity build links: go at
// offset 0, RESOURCE sections well-formed, shellcode roundtrips.
func TestLinkRealObject(t *testing.T) {
	shellcode := []byte{0x90, 0x90, 0xC3}
	out, o := linkReal(t, shellcode, nil)
	raw, err := os.ReadFile(filepath.Join(o.ObjDir, "loader.x64.o"))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := ParseObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	var text []byte
	var goOff uint32
	var goSec int16
	found := false
	for _, s := range obj.Symbols {
		if s.Name == "go" {
			goOff, goSec, found = s.Value, s.Section, true
		}
	}
	if !found || goSec < 1 || int(goSec) > len(obj.Sections) {
		t.Fatal("go symbol missing")
	}
	text = obj.Sections[goSec-1].Data
	if len(text) == 0 {
		t.Fatal("go section empty")
	}
	// Entry bytes equal go's first 16 bytes (+gofirst rotation).
	for i := 0; i < 16; i++ {
		if out[i] != text[int(goOff)+i] {
			t.Fatalf("entry byte %d: %#x != go+%d %#x", i, out[i], i, text[int(goOff)+i])
		}
	}
	// Walk the layout: code+rdata+data, then dll/mask/pico.
	// Re-derive section sizes the way the linker merged them.
	l := NewLinker()
	if err := l.MergeObject(raw, true); err != nil {
		t.Fatal(err)
	}
	dllOff := len(l.code) + len(l.rdata) + len(l.data)
	if binary.LittleEndian.Uint32(out[dllOff:dllOff+4]) != uint32(len(shellcode)) {
		t.Fatal("dll RESOURCE header wrong")
	}
	maskOff := dllOff + 4 + len(shellcode)
	if binary.LittleEndian.Uint32(out[maskOff:maskOff+4]) != 128 {
		t.Fatal("mask RESOURCE header wrong")
	}
	mask := out[maskOff+4 : maskOff+4+128]
	dec := XORBytes(out[dllOff+4:maskOff], mask)
	if string(dec) != string(shellcode) {
		t.Fatal("shellcode does not roundtrip")
	}
	picoOff := maskOff + 4 + 128
	if string(out[picoOff:]) != string(BuildPICOStub()) {
		t.Fatal("pico section is not the stub")
	}
	if len(out) != picoOff+len(BuildPICOStub()) {
		t.Fatalf("trailing bytes: %d", len(out))
	}
	if out[0] == 'M' && out[1] == 'Z' {
		t.Fatal("blob has an MZ header")
	}
}

// TestCompileMatrix builds every meaningful option combination.
func TestCompileMatrix(t *testing.T) {
	needMingw(t)
	shellcode := []byte{0xC3}
	cases := map[string]func(*Options){
		"defaults":   func(o *Options) {},
		"no-ror13":   func(o *Options) { o.ROR13 = false },
		"rwx":        func(o *Options) { o.NoRWX = false },
		"cfg":        func(o *Options) { o.CFG = true },
		"no-cleanup": func(o *Options) { o.Cleanup = false },
		"pico-none":  func(o *Options) { o.PICO = "none" },
		"no-xor":     func(o *Options) { o.XOR = false },
		"host":       func(o *Options) { o.Inject = "host" },
		"host-rwx-noxor": func(o *Options) {
			o.Inject = "host"
			o.NoRWX = false
			o.XOR = false
		},
		"trio": func(o *Options) {
			o.Hooks, o.SleepMask, o.Spoof = true, true, true
		},
		"everything": func(o *Options) {
			o.CFG = true
			o.Hooks, o.SleepMask, o.Spoof = true, true, true
			o.PICO = "none"
		},
		"everything-host": func(o *Options) {
			o.Inject = "host"
			o.CFG = true
			o.Hooks, o.SleepMask, o.Spoof = true, true, true
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			objDir := t.TempDir()
			o := Options{
				Shellcode: shellcode, SrcDir: "src", ObjDir: objDir,
				MaskLen: 32, XOR: true, PICO: "stub",
				ROR13: true, NoRWX: true, Cleanup: true, Inject: "self",
			}
			mutate(&o)
			if err := o.Compile(); err != nil {
				t.Fatalf("compile: %v", err)
			}
			out, err := o.Build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if len(out) < 512 {
				t.Fatalf("blob suspiciously small: %d", len(out))
			}
			// No plaintext API names leak in ROR13 mode.
			if o.ROR13 {
				for _, s := range []string{"NtAllocateVirtualMemory", "VirtualProtect", "LoadLibraryA"} {
					for i := 0; i+len(s) <= len(out); i++ {
						if string(out[i:i+len(s)]) == s {
							t.Fatalf("plaintext API %q in blob", s)
						}
					}
				}
			}
		})
	}
}
