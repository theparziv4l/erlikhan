package palace

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseFixture(t *testing.T) {
	obj, err := ParseObject(loaderFixture())
	if err != nil {
		t.Fatal(err)
	}
	if len(obj.Sections) != 4 || len(obj.Symbols) != 10 {
		t.Fatalf("sections=%d symbols=%d", len(obj.Sections), len(obj.Symbols))
	}
	if obj.Sections[0].Name != ".text" || len(obj.Sections[0].Relocs) != 2 {
		t.Fatalf("bad .text: %+v", obj.Sections[0])
	}
	if obj.Symbols[5].Name != "go" || obj.Symbols[9].Name != "_DLL_" {
		t.Fatalf("bad symbols: %+v", obj.Symbols)
	}
	if _, err := ParseObject([]byte("MZ")); err == nil {
		t.Fatal("non-COFF accepted")
	}
}

func TestLinkREL32(t *testing.T) {
	l := NewLinker()
	if err := l.MergeObject(loaderFixture(), true); err != nil {
		t.Fatal(err)
	}
	dll := PrependLen([]byte{0xAA, 0xBB})
	out, err := l.Assemble(map[string][]byte{"dll": dll}, []string{"dll"})
	if err != nil {
		t.Fatal(err)
	}
	// Layout: code 16, rdata 8, data 4, dll 6.
	if len(out) != 34 {
		t.Fatalf("len %d", len(out))
	}
	call := int32(binary.LittleEndian.Uint32(out[1:5]))
	if call != 1 { // helper(6) - (1+4)
		t.Fatalf("call disp %d, want 1", call)
	}
	mov := int32(binary.LittleEndian.Uint32(out[8:12]))
	if mov != 12 { // counter(24) - (8+4)
		t.Fatalf("mov disp %d, want 12", mov)
	}
	if off, ok := l.SymbolOffset("_DLL_"); !ok || off != 28 {
		t.Fatalf("_DLL_ = %d,%v, want 28", off, ok)
	}
	if string(out[28:]) != string(dll) {
		t.Fatal("dll section misplaced")
	}
}

func TestLinkGoFirstOrdering(t *testing.T) {
	l := NewLinker()
	if err := l.MergeObject(orderedFixture(), true); err != nil {
		t.Fatal(err)
	}
	out, err := l.AssembleCode()
	if err != nil {
		t.Fatal(err)
	}
	// go's section lays out first: E8 at offset 0.
	if out[0] != 0xE8 || out[5] != 0xC3 {
		t.Fatalf("ordering failed: %x", out[:6])
	}
	call := int32(binary.LittleEndian.Uint32(out[1:5]))
	if call != 1 { // helper(6) - (1+4)
		t.Fatalf("call disp %d, want 1", call)
	}
	mov := int32(binary.LittleEndian.Uint32(out[8:12]))
	if mov != 4 { // counter(16) - (8+4)
		t.Fatalf("mov disp %d, want 4", mov)
	}
	if off, _ := l.SymbolOffset("go"); off != 0 {
		t.Fatalf("go at %d", off)
	}
	// Without gofirst, file order wins and go sits at 7.
	l = NewLinker()
	if err := l.MergeObject(orderedFixture(), false); err != nil {
		t.Fatal(err)
	}
	if _, err := l.AssembleCode(); err != nil {
		t.Fatal(err)
	}
	if off, _ := l.SymbolOffset("go"); off != 7 {
		t.Fatalf("go at %d, want 7", off)
	}
}

// TestLinkSectionAddend proves the universal REL32 formula: the
// field bytes are a signed addend, so section-symbol relocs land on
// the target's section offset (real compilers emit these for every
// global access).
func TestLinkSectionAddend(t *testing.T) {
	raw := buildFixtureO2([]fixtureSection{
		{name: ".text", data: []byte{0x8B, 0x05, 4, 0, 0, 0, 0xC3}, chars: fixText,
			relocs: []Reloc{{Offset: 2, SymIndex: 2, Type: relRel32}}},
		{name: ".data", data: make([]byte, 8), chars: fixData},
		{name: "dll", chars: fixRes},
	}, []Symbol{
		{Name: "go", Section: 1, StorageClass: storageClassExt},
	})
	l := NewLinker()
	if err := l.MergeObject(raw, true); err != nil {
		t.Fatal(err)
	}
	out, err := l.AssembleCode()
	if err != nil {
		t.Fatal(err)
	}
	// .data lays out at 7; field addend 4 targets data+4 = 11.
	got := int32(binary.LittleEndian.Uint32(out[2:6]))
	if got != 5 { // 7 + 4 - (2+4)
		t.Fatalf("disp %d, want 5", got)
	}
	// The CPU lands exactly on data+4.
	if ea := 6 + int(got); ea != 11 {
		t.Fatalf("effective address %d, want 11", ea)
	}
}

func TestLinkMultiObject(t *testing.T) {
	l := NewLinker()
	if err := l.MergeObject(loaderFixture(), true); err != nil {
		t.Fatal(err)
	}
	if err := l.MergeObject(picoFixture(), false); err != nil {
		t.Fatal(err)
	}
	out, err := l.AssembleCode()
	if err != nil {
		t.Fatal(err)
	}
	// Second object's code appends after the first (16 + pad + 2).
	off, ok := l.SymbolOffset("setup_memory")
	if !ok {
		t.Fatal("setup_memory missing")
	}
	if out[off] != 0xC3 {
		t.Fatalf("setup_memory points at %#x", out[off])
	}
}

func TestLinkRejects(t *testing.T) {
	// Absolute relocation: not PIC.
	abs := buildFixtureO(fixtureSpec{
		text:    []byte{0, 0, 0, 0, 0, 0, 0, 0},
		syms:    []Symbol{{Name: "go", Section: 1, StorageClass: storageClassExt}},
		relocs:  []Reloc{{Offset: 0, SymIndex: 5, Type: relAddr64}},
		secSyms: true,
	})
	l := NewLinker()
	if err := l.MergeObject(abs, false); err == nil || !strings.Contains(err.Error(), "PIC") {
		t.Fatalf("ADDR64: got %v", err)
	}
	// Unresolved external.
	und := buildFixtureO(fixtureSpec{
		text:    []byte{0xE8, 0, 0, 0, 0},
		syms:    []Symbol{{Name: "printf", Section: 0, StorageClass: storageClassExt}},
		relocs:  []Reloc{{Offset: 1, SymIndex: 5, Type: relRel32}},
		secSyms: true,
	})
	l = NewLinker()
	if err := l.MergeObject(und, false); err != nil {
		t.Fatal(err)
	}
	if _, err := l.AssembleCode(); err == nil || !strings.Contains(err.Error(), "unresolved external") {
		t.Fatalf("unresolved: got %v", err)
	}
	// Duplicate symbol across objects.
	l = NewLinker()
	if err := l.MergeObject(loaderFixture(), false); err != nil {
		t.Fatal(err)
	}
	if err := l.MergeObject(loaderFixture(), false); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate: got %v", err)
	}
	// gofirst without go.
	l = NewLinker()
	if err := l.MergeObject(picoFixture(), true); err == nil || !strings.Contains(err.Error(), "gofirst") {
		t.Fatalf("gofirst: got %v", err)
	}
}
