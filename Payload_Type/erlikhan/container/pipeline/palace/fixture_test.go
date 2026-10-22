package palace

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// fixtureSection is one synthetic COFF section.
type fixtureSection struct {
	name   string
	data   []byte
	chars  uint32
	relocs []Reloc
}

const (
	fixText  = 0x20 | 0x20000000 | 0x40000000 | 0x00100000 // CODE|EXEC|READ|ALIGN_1
	fixRData = 0x40 | 0x40000000 | 0x00100000
	fixData  = 0x40 | 0x40000000 | 0x80000000 | 0x00100000
	fixRes   = 0x40 | 0x40000000 | 0x00100000
)

// buildFixtureO2 assembles a minimal AMD64 COFF object from explicit
// sections. Names longer than 8 bytes go through the string table,
// exercising both the /offset section form and long symbol names.
func buildFixtureO2(sections []fixtureSection, syms []Symbol) []byte {
	strOff := map[string]uint32{}
	var strtab []byte
	intern := func(s string) uint32 {
		if off, ok := strOff[s]; ok {
			return off
		}
		off := uint32(4 + len(strtab))
		strOff[s] = off
		strtab = append(strtab, s...)
		strtab = append(strtab, 0)
		return off
	}
	for _, s := range sections {
		if len(s.name) > 8 {
			intern(s.name)
		}
	}
	for _, s := range syms {
		if len(s.Name) > 8 {
			intern(s.Name)
		}
	}
	// Layout: headers, raw data, relocs, symbols, string table.
	rawBase := 20 + len(sections)*40
	secOff := make([]int, len(sections))
	off := rawBase
	for i, s := range sections {
		secOff[i] = off
		off += len(s.data)
	}
	relOff := make([]int, len(sections))
	for i, s := range sections {
		relOff[i] = off
		off += len(s.relocs) * 10
	}
	symOff := off

	var out []byte
	put16 := func(v uint16) {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], v)
		out = append(out, b[:]...)
	}
	put32 := func(v uint32) {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], v)
		out = append(out, b[:]...)
	}
	// File header: Machine, NumSections, Timestamp, SymPtr,
	// NumSyms, OptSize, Characteristics.
	put16(0x8664)
	put16(uint16(len(sections)))
	put32(0)
	put32(uint32(symOff))
	put32(uint32(1 + len(sections) + len(syms)))
	put16(0)
	put16(0)
	for i, s := range sections {
		if len(s.name) > 8 {
			name := fmt.Sprintf("/%d", strOff[s.name])
			var b [8]byte
			copy(b[:], name)
			out = append(out, b[:]...)
		} else {
			var b [8]byte
			copy(b[:], s.name)
			out = append(out, b[:]...)
		}
		put32(uint32(len(s.data)))
		put32(0)
		put32(uint32(len(s.data)))
		put32(uint32(secOff[i]))
		put32(uint32(relOff[i]))
		put32(0)
		put16(uint16(len(s.relocs)))
		put16(0)
		put32(s.chars)
	}
	for _, s := range sections {
		out = append(out, s.data...)
	}
	for _, s := range sections {
		for _, r := range s.relocs {
			put32(r.Offset)
			put32(r.SymIndex)
			put16(r.Type)
		}
	}
	symName := func(s string) {
		if off, ok := strOff[s]; ok && len(s) > 8 {
			put32(0)
			put32(off)
			return
		}
		var b [8]byte
		copy(b[:], s)
		out = append(out, b[:]...)
	}
	sym := func(name string, val uint32, sec int16, class uint8) {
		symName(name)
		put32(val)
		put16(uint16(sec))
		put16(0)
		out = append(out, class, 0)
	}
	sym("", 0, 0, 0)
	for i, s := range sections {
		sym(s.name, 0, int16(i+1), storageClassStatic)
	}
	for _, s := range syms {
		sym(s.Name, s.Value, s.Section, s.StorageClass)
	}
	put32(uint32(4 + len(strtab)))
	out = append(out, strtab...)
	return out
}

// fixtureSpec describes one synthetic COFF object (single .text).
type fixtureSpec struct {
	text    []byte
	rdata   []byte
	data    []byte
	syms    []Symbol
	relocs  []Reloc // all in .text
	secSyms bool    // include section symbols
}

// buildFixtureO assembles a minimal AMD64 COFF object: .text, .rdata,
// .data and a zero-length dll marker section.
func buildFixtureO(spec fixtureSpec) []byte {
	chars := uint32(0x20 | 0x20000000 | 0x40000000 | 0x00500000)
	rchars := uint32(0x40 | 0x40000000 | 0x00400000)
	dchars := uint32(0x40 | 0x40000000 | 0x80000000 | 0x00300000)
	sections := []fixtureSection{
		{name: ".text", data: spec.text, chars: chars, relocs: spec.relocs},
		{name: ".rdata", data: spec.rdata, chars: rchars},
		{name: ".data", data: spec.data, chars: dchars},
		{name: "dll", chars: fixRes},
	}
	if !spec.secSyms {
		// Without section symbols the indices shift; the builder
		// always emits them, so pad the expectation instead.
		panic("secSyms=false unsupported")
	}
	return buildFixtureO2(sections, spec.syms)
}

// loaderFixture returns the canonical test object:
//
//	.text: go@0: E8[disp→helper] C3 | helper@6: 8B 05[disp→counter] C3
//	.rdata: msg@0 "Hi\0"
//	.data: counter@0
//	dll: _DLL_@0 (resource marker)
//
// Symbol indices: 0 null, 1-4 section syms, 5 go, 6 helper, 7 msg,
// 8 counter, 9 _DLL_.
func loaderFixture() []byte {
	text := []byte{0xE8, 0, 0, 0, 0, 0xC3, 0x8B, 0x05, 0, 0, 0, 0, 0xC3, 0, 0, 0}
	return buildFixtureO(fixtureSpec{
		text:  text,
		rdata: []byte{'H', 'i', 0, 0, 0, 0, 0, 0},
		data:  []byte{0x78, 0x56, 0x34, 0x12},
		syms: []Symbol{
			{Name: "go", Section: 1, StorageClass: storageClassExt},
			{Name: "helper", Value: 6, Section: 1, StorageClass: storageClassExt},
			{Name: "msg", Section: 2, StorageClass: storageClassExt},
			{Name: "counter", Section: 3, StorageClass: storageClassExt},
			{Name: "_DLL_", Section: 4, StorageClass: storageClassExt},
		},
		relocs: []Reloc{
			{Offset: 1, SymIndex: 6, Type: relRel32},
			{Offset: 8, SymIndex: 8, Type: relRel32},
		},
		secSyms: true,
	})
}

// orderedFixture mimics -ffunction-sections: helper's section comes
// first in file order, go's second; +gofirst must lay go's section
// at offset 0. Symbol indices: 0 null, 1-5 section syms, 6 go,
// 7 helper, 8 msg, 9 counter, 10 _DLL_.
func orderedFixture() []byte {
	return buildFixtureO2([]fixtureSection{
		{name: ".text$helper", data: []byte{0x8B, 0x05, 0, 0, 0, 0, 0xC3}, chars: fixText,
			relocs: []Reloc{{Offset: 2, SymIndex: 9, Type: relRel32}}},
		{name: ".text$go", data: []byte{0xE8, 0, 0, 0, 0, 0xC3}, chars: fixText,
			relocs: []Reloc{{Offset: 1, SymIndex: 7, Type: relRel32}}},
		{name: ".rdata", data: []byte{'H', 'i', 0}, chars: fixRData},
		{name: ".data", data: []byte{0x78, 0x56, 0x34, 0x12}, chars: fixData},
		{name: "dll", chars: fixRes},
	}, []Symbol{
		{Name: "go", Section: 2, StorageClass: storageClassExt},
		{Name: "helper", Section: 1, StorageClass: storageClassExt},
		{Name: "msg", Section: 3, StorageClass: storageClassExt},
		{Name: "counter", Section: 4, StorageClass: storageClassExt},
		{Name: "_DLL_", Section: 5, StorageClass: storageClassExt},
	})
}

// picoFixture is a tiny second object with distinct symbols for
// multi-object and PICO tests: setup_hooks@0, setup_memory@1.
func picoFixture() []byte {
	return buildFixtureO(fixtureSpec{
		text: []byte{0xC3, 0xC3},
		syms: []Symbol{
			{Name: "setup_hooks", Section: 1, StorageClass: storageClassExt},
			{Name: "setup_memory", Value: 1, Section: 1, StorageClass: storageClassExt},
		},
		secSyms: true,
	})
}
