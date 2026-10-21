package main

import (
	"math/bits"
	"runtime"
	"strings"
	"testing"
)

func sectionByName(img *coffImage, name string) *coffSection {
	for i := range img.sections {
		if img.sections[i].name == name {
			return &img.sections[i]
		}
	}
	return nil
}

func TestParseCoffFixture(t *testing.T) {
	img, err := parseCoff(bofFixture)
	if err != nil {
		t.Fatal(err)
	}
	text := sectionByName(img, ".text")
	if text == nil || !text.mapped || len(text.data) == 0 {
		t.Fatalf(".text missing: %+v", img.sections)
	}
	if len(text.relocs) != 6 {
		t.Fatalf(".text relocs = %d, want 6", len(text.relocs))
	}
	for _, r := range text.relocs {
		if r.typ != relAMD64Rel32 {
			t.Fatalf("reloc type %d, want REL32", r.typ)
		}
		if int(r.sym) >= len(img.symbols) {
			t.Fatalf("reloc symbol %d out of range", r.sym)
		}
	}
	rdata := sectionByName(img, ".rdata")
	if rdata == nil || !rdata.mapped {
		t.Fatal(".rdata must map (format strings live there)")
	}
	if s := sectionByName(img, ".llvm_addrsig"); s == nil {
		t.Fatal("long /NNN section name must resolve")
	}
	if len(img.symbols) != 22 {
		t.Fatalf("symbols = %d, want 22 (aux placeholders keep indices aligned)", len(img.symbols))
	}
	for _, skip := range []string{".pdata", ".xdata", ".llvm_addrsig"} {
		if s := sectionByName(img, skip); s != nil && s.mapped {
			t.Fatalf("%s must not map", skip)
		}
	}
	foundGo := false
	undef := map[string]bool{}
	for _, s := range img.symbols {
		if s.name == "go" && s.section == 1 && s.value == 0 {
			foundGo = true
		}
		if s.section == 0 {
			undef[s.name] = true
		}
	}
	if !foundGo {
		t.Fatal("entrypoint go not defined in section 1")
	}
	for _, want := range []string{"BeaconDataParse", "BeaconDataInt", "BeaconDataExtract", "BeaconPrintf"} {
		if !undef[want] {
			t.Fatalf("undefined import %s missing (have %v)", want, undef)
		}
	}
}

func TestParseCoffErrors(t *testing.T) {
	if _, err := parseCoff(nil); err == nil {
		t.Fatal("empty should fail")
	}
	if _, err := parseCoff(bofFixture[:10]); err == nil {
		t.Fatal("truncated header should fail")
	}
	badMachine := append([]byte(nil), bofFixture...)
	badMachine[0], badMachine[1] = 0x4c, 0x01 // i386
	if _, err := parseCoff(badMachine); err == nil || !strings.Contains(err.Error(), "machine") {
		t.Fatalf("i386 should fail with machine error, got %v", err)
	}
	badOpt := append([]byte(nil), bofFixture...)
	badOpt[16] = 0x70 // fake optional header size
	if _, err := parseCoff(badOpt); err == nil {
		t.Fatal("optional header should fail")
	}
	truncated := append([]byte(nil), bofFixture[:400]...)
	if _, err := parseCoff(truncated); err == nil {
		t.Fatal("truncated sections should fail")
	}
}

func TestDecodeCoffArgs(t *testing.T) {
	buf, err := decodeCoffArgs("")
	if err != nil || len(buf) != 4 {
		t.Fatalf("empty: %v %v", buf, err)
	}
	// Matches the container's golden vector: i32 42 + "hi".
	buf, err = decodeCoffArgs("0b0000002a00000003000000686900")
	if err != nil || len(buf) != 15 {
		t.Fatalf("vector: %v %v", buf, err)
	}
	for _, bad := range []string{"zz", "0b00", "0b0000002a00", "02000000ffff00"} {
		if _, err := decodeCoffArgs(bad); err == nil {
			t.Fatalf("input %q should fail", bad)
		}
	}
}

func TestTaskTimeout(t *testing.T) {
	if taskTimeout("") != 30 || taskTimeout("{}") != 30 {
		t.Fatal("defaults")
	}
	if taskTimeout(`{"timeout": 45}`) != 45 || taskTimeout(`{"timeout": "60"}`) != 60 {
		t.Fatal("shapes")
	}
	if taskTimeout(`{"timeout": 0}`) != 1 || taskTimeout(`{"timeout": 999999}`) != 86400 {
		t.Fatal("clamp")
	}
	if taskTimeout(`{"timeout": "bogus"}`) != 30 || taskTimeout("not json") != 30 {
		t.Fatal("fallback")
	}
}

func TestCoffHostOK(t *testing.T) {
	err := coffHostOK()
	if runtime.GOARCH == "amd64" && err != nil {
		t.Fatalf("amd64 should pass: %v", err)
	}
	if runtime.GOARCH != "amd64" && err == nil {
		t.Fatal("non-amd64 should fail")
	}
}

func TestFormatBeaconWordSize(t *testing.T) {
	if bits.UintSize != 64 {
		t.Skip("slot bit patterns are width-dependent")
	}
	mem, _, _ := fakeBeaconMem(t)
	if got := formatBeacon("n=%d", []uintptr{^uintptr(0)}, mem); got != "n=-1" {
		t.Fatalf("negative: %q", got)
	}
	if got := formatBeacon("n=%u", []uintptr{^uintptr(0)}, mem); got != "n=18446744073709551615" {
		t.Fatalf("unsigned: %q", got)
	}
	if got := formatBeacon("n=%x", []uintptr{^uintptr(0)}, mem); got != "n=ffffffffffffffff" {
		t.Fatalf("hex: %q", got)
	}
}

func fakeBeaconMem(t *testing.T) (beaconReader, map[uintptr]string, map[uintptr]string) {
	t.Helper()
	bytes := map[uintptr]string{0x1000: "hi", 0x2000: "end"}
	wide := map[uintptr]string{0x3000: "wide"}
	mem := beaconReader{
		bytes: func(p uintptr) string { return bytes[p] },
		wide:  func(p uintptr) string { return wide[p] },
	}
	return mem, bytes, wide
}

func TestFormatBeacon(t *testing.T) {
	mem, _, _ := fakeBeaconMem(t)
	for _, tc := range []struct {
		name   string
		format string
		slots  []uintptr
		want   string
	}{
		{"plain", "hello", nil, "hello"},
		{"percent", "100%%", nil, "100%"},
		{"dangling", "abc%", nil, "abc%"},
		{"int", "n=%d", []uintptr{42}, "n=42"},
		{"hex", "n=%x", []uintptr{42}, "n=2a"},
		{"hex upper", "n=%X", []uintptr{42}, "n=2A"},
		{"hex width", "n=%08x", []uintptr{42}, "n=0000002a"},
		{"octal", "n=%o", []uintptr{8}, "n=10"},
		{"ptr", "p=%p", []uintptr{0x1234}, "p=0x1234"},
		{"char", "c=%c", []uintptr{65}, "c=A"},
		{"string", "z=%s", []uintptr{0x1000}, "z=hi"},
		{"wide", "w=%ls", []uintptr{0x3000}, "w=wide"},
		{"wide S", "w=%S", []uintptr{0x3000}, "w=wide"},
		{"multi", "n=%d z=%s tail=%d %s", []uintptr{42, 0x1000, 7, 0x2000},
			"n=42 z=hi tail=7 end"},
		{"unknown literal", "%q %d", []uintptr{5}, "%q 5"},
		{"float literal", "%f %d", []uintptr{5}, "%f 5"},
		{"missing", "%d %d", []uintptr{1}, "1 (missing)"},
		{"short mask", "%hd", []uintptr{0x1FFFF}, "65535"},
		{"byte mask", "%hhd", []uintptr{0x1FF}, "255"},
		{"star width", "%*d", []uintptr{5, 42}, "   42"},
		{"left", "%-5d|", []uintptr{42}, "42   |"},
	} {
		if got := formatBeacon(tc.format, tc.slots, mem); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
