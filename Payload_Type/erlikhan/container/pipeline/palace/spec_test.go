package palace

import (
	"archive/zip"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "loader.x64.o"), loaderFixture(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pico.x64.o"), picoFixture(), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEvalDefaultShape(t *testing.T) {
	dir := fixtureDir(t)
	shellcode := []byte{0x90, 0x90, 0xC3, 0xCC, 0x01, 0x02}
	ev := NewEvaluator(dir, shellcode, true)
	if err := ev.Eval(DefaultSpec()); err != nil {
		t.Fatal(err)
	}
	named, order := ev.NamedSections()
	if len(order) != 3 || order[0] != "dll" || order[1] != "mask" || order[2] != "pico" {
		t.Fatalf("order %v", order)
	}
	// Mask section: RESOURCE header + 128 random bytes.
	mask := named["mask"]
	if len(mask) != 4+128 || binary.LittleEndian.Uint32(mask[:4]) != 128 {
		t.Fatalf("mask section len %d", len(mask))
	}
	// DLL section decrypts to the shellcode with the mask key.
	dll := named["dll"]
	if binary.LittleEndian.Uint32(dll[:4]) != uint32(len(shellcode)) {
		t.Fatalf("dll len header %d", binary.LittleEndian.Uint32(dll[:4]))
	}
	dec := XORBytes(dll[4:], mask[4:])
	if string(dec) != string(shellcode) {
		t.Fatal("dll section does not decrypt to shellcode")
	}
	// PICO falls back to the stub (no pico.spec on disk).
	if string(named["pico"]) != string(BuildPICOStub()) {
		t.Fatal("pico is not the stub")
	}
	out, err := ev.Assembly()
	if err != nil {
		t.Fatal(err)
	}
	if out[0] != 0xE8 {
		t.Fatalf("entry is not go: %#x", out[0])
	}
}

func TestEvalDirectives(t *testing.T) {
	dir := fixtureDir(t)
	ev := NewEvaluator(dir, []byte{1, 2, 3}, true)
	spec := "x64:\n" +
		"    load \"loader.x64.o\"\n" +
		"        make pic +gofirst +optimize\n" +
		"    dfr \"resolve\" \"ror13\"\n" +
		"    attach \"DLL$Func\" \"_sym\"\n" +
		"    addhook \"DLL$F\" \"_s\"\n" +
		"    generate $K 16\n" +
		"    push $K\n" +
		"        preplen\n" +
		"        link \"mask\"\n" +
		"    export\n"
	if err := ev.Eval(spec); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Assembly(); err != nil {
		t.Fatal(err)
	}
	// Merge form appends a second object.
	ev = NewEvaluator(dir, []byte{1}, true)
	if err := ev.Eval("x64:\n    merge \"pico.x64.o\"\n    export\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Assembly(); err != nil {
		t.Fatal(err)
	}
}

func TestEvalPICOSubSpec(t *testing.T) {
	dir := fixtureDir(t)
	pico := "x64:\n" +
		"    load \"pico.x64.o\"\n" +
		"        make object +disco\n" +
		"    exportfunc \"setup_hooks\" \"__tag_setup_hooks\"\n" +
		"    exportfunc \"setup_memory\" \"__tag_setup_memory\"\n" +
		"    export\n"
	if err := os.WriteFile(filepath.Join(dir, "pico.spec"), []byte(pico), 0o644); err != nil {
		t.Fatal(err)
	}
	ev := NewEvaluator(dir, []byte{0xC3}, true)
	if err := ev.Eval("x64:\n    load \"loader.x64.o\"\n        make pic +gofirst\n    run \"pico.spec\"\n        link \"pico\"\n    export\n"); err != nil {
		t.Fatal(err)
	}
	named, _ := ev.NamedSections()
	blob := named["pico"]
	if len(blob) != 8+16+2 {
		t.Fatalf("pico blob len %d", len(blob))
	}
	if total := binary.LittleEndian.Uint32(blob[0:4]); total != uint32(len(blob)) {
		t.Fatalf("total %d", total)
	}
	if n := binary.LittleEndian.Uint32(blob[4:8]); n != 2 {
		t.Fatalf("exports %d", n)
	}
	if tag := binary.LittleEndian.Uint32(blob[8:12]); tag != 0 {
		t.Fatalf("tag0 %d", tag)
	}
	if off := binary.LittleEndian.Uint32(blob[12:16]); off != 0 {
		t.Fatalf("off0 %d", off)
	}
	if off := binary.LittleEndian.Uint32(blob[20:24]); off != 1 {
		t.Fatalf("off1 %d", off)
	}
}

func TestEvalMergeLib(t *testing.T) {
	dir := fixtureDir(t)
	zpath := filepath.Join(dir, "lib.zip")
	zf, err := os.Create(zpath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	w, err := zw.Create("pico.x64.o")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(picoFixture()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zf.Close()
	ev := NewEvaluator(dir, []byte{1}, true)
	if err := ev.Eval("x64:\n    mergelib \"lib.zip\"\n    export\n"); err != nil {
		t.Fatal(err)
	}
	out, err := ev.Assembly()
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0] != 0xC3 {
		t.Fatalf("mergelib output %x", out)
	}
}

func TestEvalRejects(t *testing.T) {
	dir := fixtureDir(t)
	cases := []struct {
		name string
		spec string
		want string
	}{
		{"no header", "load \"a.o\"\n", "x64:"},
		{"unknown directive", "x64:\n    frobnicate\n", "unknown directive"},
		{"make without load", "x64:\n    make pic\n", "without a preceding load"},
		{"bare merge without load", "x64:\n    merge\n", "without a preceding load"},
		{"bad modifier", "x64:\n    load \"loader.x64.o\"\n    make pic +warp\n", "unknown modifier"},
		{"missing object", "x64:\n    load \"nope.o\"\n", "no such file"},
		{"generate bad var", "x64:\n    generate MASK 8\n", "must start with $"},
		{"generate bad len", "x64:\n    generate $M 0\n", "bad length"},
		{"push unknown var", "x64:\n    push $NOPE\n", "unknown variable"},
		{"push unknown section", "x64:\n    push nope\n", "unknown section"},
		{"xor empty stack", "x64:\n    generate $M 8\n    xor $M\n", "empty stack"},
		{"xor unknown key", "x64:\n    push $DLL\n    xor $NOPE\n", "unknown or empty key"},
		{"preplen empty", "x64:\n    preplen\n", "empty stack"},
		{"link empty", "x64:\n    link \"dll\"\n", "empty stack"},
		{"exportfunc dup", "x64:\n    exportfunc \"a\" \"t\"\n    exportfunc \"a\" \"t\"\n", "duplicate export"},
		{"after export", "x64:\n    export\n    export\n", "after export"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := NewEvaluator(dir, []byte{1, 2}, true)
			err := ev.Eval(tc.spec)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
	// Missing run target with PICO off pushes empty.
	ev := NewEvaluator(dir, []byte{1}, false)
	if err := ev.Eval("x64:\n    run \"pico.spec\"\n        link \"pico\"\n    export\n"); err != nil {
		t.Fatal(err)
	}
	if n, _ := ev.NamedSections(); len(n["pico"]) != 0 {
		t.Fatal("pico off should link empty")
	}
}
