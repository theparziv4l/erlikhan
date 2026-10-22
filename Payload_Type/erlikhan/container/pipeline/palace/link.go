package palace

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Buffer ids for merged sections.
const (
	bufCode = iota
	bufRData
	bufData
	bufDropped = -1
	// bufResource marks GETRESOURCE marker sections (dll/mask/pico):
	// zero-length placeholders the spec fills at assembly.
	bufResource = -2
)

// resourceSections are the named sections the C loader reads via
// GETRESOURCE. Symbols defined in them resolve to the final blob
// offsets of the spec-linked data.
var resourceSections = map[string]bool{"dll": true, "mask": true, "pico": true}

type mergedSym struct {
	buf int
	off int
	res string // resource section when buf == bufResource
}

type pendingReloc struct {
	buf        int
	site       int // offset within buf of the 4-byte field
	global     string
	staticObj  int // >= 0 when referencing a namespaced static
	staticName string
	secObj     int // >= 0 when referencing a section symbol
	secIdx     int
	typ        uint16
}

type objMerge struct {
	secBuf  []int // per section: buf id, bufDropped, or bufResource
	secBase []int // per section: offset in target buffer
	statics map[string]mergedSym
}

// Linker merges COFF objects into flat code/rdata/data buffers and
// applies relocations once the final layout (including spec-linked
// named sections) is known.
type Linker struct {
	code  []byte
	rdata []byte
	data  []byte
	objs  []objMerge
	globs map[string]mergedSym
	undef map[string]bool
	pend  []pendingReloc
	final map[string]int
	// Notes collects non-fatal observations (e.g. REL32_N use).
	Notes []string
}

// NewLinker returns an empty linker.
func NewLinker() *Linker {
	return &Linker{globs: map[string]mergedSym{}, undef: map[string]bool{}}
}

// classify routes a section to a merge buffer.
func classify(name string, chars uint32) (int, error) {
	if resourceSections[name] {
		return bufResource, nil
	}
	if chars&scnLnkRemove != 0 {
		return bufDropped, nil
	}
	switch name {
	case ".drectve", ".drective", ".comment", ".pdata", ".xdata", ".sxdata", ".voltbl":
		return bufDropped, nil
	}
	if strings.HasPrefix(name, ".debug") {
		return bufDropped, nil
	}
	if strings.HasPrefix(name, ".pdata$") || strings.HasPrefix(name, ".xdata$") {
		return bufDropped, nil
	}
	if strings.HasPrefix(name, ".idata") || strings.HasPrefix(name, ".edata") {
		return 0, fmt.Errorf("section %q holds import tables: object is not PIC", name)
	}
	if name == ".reloc" {
		return 0, fmt.Errorf("section .reloc is not PIC-compatible")
	}
	if strings.HasPrefix(name, ".tls$") || name == ".tls" {
		return 0, fmt.Errorf("section %q: TLS is unsupported in shellcode", name)
	}
	if strings.Contains(name, ".refptr") || strings.Contains(name, "__imp_") || strings.Contains(name, ".vptr") {
		return 0, fmt.Errorf("section %q: absolute indirection is incompatible with PIC (use a unity build)", name)
	}
	if chars&scnCntCode != 0 || chars&scnMemExecute != 0 {
		return bufCode, nil
	}
	if chars&scnMemWrite != 0 || chars&scnCntUninitData != 0 {
		return bufData, nil
	}
	return bufRData, nil
}

func (l *Linker) bufPtr(buf int) *[]byte {
	switch buf {
	case bufCode:
		return &l.code
	case bufRData:
		return &l.rdata
	default:
		return &l.data
	}
}

// MergeObject parses and merges one COFF object. When goFirst is set
// the code section defining go is laid out first, so the entry point
// is the first byte with no stub needed (the spec's +gofirst).
// Whole-section ordering (with -ffunction-sections) is the only sound
// way to do this: the compiler pre-resolves intra-section calls with
// no relocs, so rotating bytes inside a section would corrupt them.
func (l *Linker) MergeObject(raw []byte, goFirst bool) error {
	obj, err := ParseObject(raw)
	if err != nil {
		return err
	}
	om := objMerge{
		secBuf:  make([]int, len(obj.Sections)),
		secBase: make([]int, len(obj.Sections)),
		statics: map[string]mergedSym{},
	}
	for i := range obj.Sections {
		buf, err := classify(obj.Sections[i].Name, obj.Sections[i].Characteristics)
		if err != nil {
			return err
		}
		om.secBuf[i] = buf
	}
	order := make([]int, len(obj.Sections))
	for i := range order {
		order[i] = i
	}
	if goFirst {
		goSec := -1
		for _, sym := range obj.Symbols {
			if sym.Name == "go" && sym.Section > 0 && int(sym.Section)-1 < len(obj.Sections) {
				if si := int(sym.Section) - 1; om.secBuf[si] == bufCode {
					goSec = si
				}
			}
		}
		if goSec < 0 {
			return fmt.Errorf("+gofirst: no go symbol in code")
		}
		ordered := []int{goSec}
		for _, i := range order {
			if i != goSec {
				ordered = append(ordered, i)
			}
		}
		order = ordered
	}
	for _, i := range order {
		sec := &obj.Sections[i]
		buf := om.secBuf[i]
		if buf == bufDropped || buf == bufResource {
			continue
		}
		bp := l.bufPtr(buf)
		if pad := -len(*bp) & (sec.Alignment() - 1); pad > 0 {
			*bp = append(*bp, make([]byte, pad)...)
		}
		om.secBase[i] = len(*bp)
		*bp = append(*bp, sec.Data...)
	}
	objIdx := len(l.objs)
	for si, sym := range obj.Symbols {
		if sym.Name == "" && sym.StorageClass == 0 {
			continue // null / aux slot
		}
		if sym.StorageClass == storageClassFile || sym.Section == symDebug || sym.Section == symAbsolute {
			continue // .file records, debug and @comp.id-style metadata
		}
		if sym.Section == symUndef {
			if sym.StorageClass == storageClassStatic {
				continue
			}
			l.undef[sym.Name] = true
			continue
		}
		sidx := int(sym.Section) - 1
		if sidx < 0 || sidx >= len(obj.Sections) {
			return fmt.Errorf("symbol %q: bad section %d", sym.Name, sym.Section)
		}
		buf := om.secBuf[sidx]
		if buf == bufDropped {
			if sym.StorageClass == storageClassStatic && strings.HasPrefix(sym.Name, ".") {
				continue // section symbol of a dropped section
			}
			return fmt.Errorf("symbol %q lives in dropped section %q", sym.Name, obj.Sections[sidx].Name)
		}
		if sym.StorageClass == storageClassStatic && strings.HasPrefix(sym.Name, ".") {
			continue // section symbols resolve via (object, section)
		}
		ms := mergedSym{buf: buf, off: int(sym.Value)}
		if buf == bufResource {
			ms.res = obj.Sections[sidx].Name
		} else {
			ms.off += om.secBase[sidx]
		}
		if sym.StorageClass == storageClassStatic {
			om.statics[sym.Name] = ms
			continue
		}
		if _, dup := l.globs[sym.Name]; dup {
			return fmt.Errorf("duplicate symbol %q (symbol %d)", sym.Name, si)
		}
		l.globs[sym.Name] = ms
	}
	// Relocations of surviving sections only; dropped sections take
	// theirs (pdata/xdata self-references) with them.
	for i := range obj.Sections {
		if buf := om.secBuf[i]; buf != bufCode && buf != bufRData && buf != bufData {
			continue
		}
		sec := &obj.Sections[i]
		for _, r := range sec.Relocs {
			if uint64(r.Offset)+4 > uint64(len(sec.Data)) {
				return fmt.Errorf("reloc in %q at %d overruns section (%d bytes)", sec.Name, r.Offset, len(sec.Data))
			}
			if int(r.SymIndex) >= len(obj.Symbols) {
				return fmt.Errorf("reloc in %q references missing symbol %d", sec.Name, r.SymIndex)
			}
			sym := obj.Symbols[r.SymIndex]
			switch r.Type {
			case relAbsolute:
				continue
			case relAddr64, relAddr32, relAddr32NB:
				return fmt.Errorf("section %q: absolute relocation against %q is incompatible with PIC (use a unity build)", sec.Name, sym.Name)
			case relRel32, relRel32_1, relRel32_2, relRel32_3, relRel32_4, relRel32_5:
			default:
				return fmt.Errorf("section %q: unsupported relocation type %d against %q", sec.Name, r.Type, sym.Name)
			}
			pr := pendingReloc{
				buf:       om.secBuf[i],
				site:      om.secBase[i] + int(r.Offset),
				typ:       r.Type,
				secObj:    -1,
				secIdx:    -1,
				staticObj: -1,
			}
			switch {
			case sym.StorageClass == storageClassStatic && strings.HasPrefix(sym.Name, ".") && sym.Section > 0:
				// Section symbol: target is the section base.
				tsi := int(sym.Section) - 1
				if om.secBuf[tsi] != bufCode && om.secBuf[tsi] != bufRData && om.secBuf[tsi] != bufData {
					return fmt.Errorf("reloc in %q targets dropped section %q", sec.Name, obj.Sections[tsi].Name)
				}
				pr.secObj, pr.secIdx = objIdx, tsi
			case sym.StorageClass == storageClassStatic:
				if _, ok := om.statics[sym.Name]; !ok {
					return fmt.Errorf("reloc in %q targets unknown static %q", sec.Name, sym.Name)
				}
				pr.staticObj, pr.staticName = objIdx, sym.Name
			case sym.Section == symUndef:
				pr.global = sym.Name
			default:
				pr.global = sym.Name
			}
			l.pend = append(l.pend, pr)
		}
	}
	l.objs = append(l.objs, om)
	return nil
}

// layout computes base offsets for every buffer and named section.
func (l *Linker) layout(named map[string][]byte, order []string) (base [3]int, namedBase map[string]int, total int) {
	base[bufCode] = 0
	base[bufRData] = len(l.code)
	base[bufData] = len(l.code) + len(l.rdata)
	total = len(l.code) + len(l.rdata) + len(l.data)
	namedBase = map[string]int{}
	for _, name := range order {
		namedBase[name] = total
		total += len(named[name])
	}
	return base, namedBase, total
}

func (l *Linker) target(pr pendingReloc, base [3]int, namedBase map[string]int) (int, error) {
	if pr.global != "" {
		ms, ok := l.globs[pr.global]
		if !ok {
			return 0, fmt.Errorf("unresolved external %q (PIC objects must not call CRT imports)", pr.global)
		}
		if ms.buf == bufResource {
			nb, ok := namedBase[ms.res]
			if !ok {
				return 0, fmt.Errorf("resource section %q was never linked", ms.res)
			}
			return nb + ms.off, nil
		}
		return base[ms.buf] + ms.off, nil
	}
	if pr.staticName != "" {
		ms := l.objs[pr.staticObj].statics[pr.staticName]
		if ms.buf == bufResource {
			nb, ok := namedBase[ms.res]
			if !ok {
				return 0, fmt.Errorf("resource section %q was never linked", ms.res)
			}
			return nb + ms.off, nil
		}
		return base[ms.buf] + ms.off, nil
	}
	if pr.secObj < 0 || pr.secObj >= len(l.objs) {
		return 0, fmt.Errorf("internal: relocation with no target")
	}
	om := l.objs[pr.secObj]
	return base[om.secBuf[pr.secIdx]] + om.secBase[pr.secIdx], nil
}

// Assemble lays out [code][rdata][data][named...] and applies every
// relocation for that exact layout, so the blob is self-contained
// and position-independent.
func (l *Linker) Assemble(named map[string][]byte, order []string) ([]byte, error) {
	base, namedBase, total := l.layout(named, order)
	out := make([]byte, 0, total)
	out = append(out, l.code...)
	out = append(out, l.rdata...)
	out = append(out, l.data...)
	for _, name := range order {
		out = append(out, named[name]...)
	}
	l.final = map[string]int{}
	for name, ms := range l.globs {
		if ms.buf == bufResource {
			if nb, ok := namedBase[ms.res]; ok {
				l.final[name] = nb + ms.off
			}
			continue
		}
		l.final[name] = base[ms.buf] + ms.off
	}
	seenN := map[uint16]bool{}
	for _, pr := range l.pend {
		s, err := l.target(pr, base, namedBase)
		if err != nil {
			return nil, err
		}
		site := base[pr.buf] + pr.site
		// The field's original bytes are a signed addend: for
		// section-symbol relocs the compiler bakes the target's
		// section offset (plus any trailing-byte adjustment, e.g.
		// -1 for disp32+imm8) into the field, so the linked value
		// is S + A - (F + 4).
		addend := int(int32(binary.LittleEndian.Uint32((*l.bufPtr(pr.buf))[pr.site : pr.site+4])))
		var v int
		switch pr.typ {
		case relRel32:
			v = s + addend - (site + 4)
		case relRel32_1, relRel32_2, relRel32_3, relRel32_4, relRel32_5:
			// Variant N: the PC sits N bytes past the field end.
			v = s + addend - (site + 4 + int(pr.typ-relRel32))
			if !seenN[pr.typ] {
				seenN[pr.typ] = true
				l.Notes = append(l.Notes, fmt.Sprintf("REL32_%d relocation used; verify on target", pr.typ-relRel32))
			}
		}
		binary.LittleEndian.PutUint32(out[site:site+4], uint32(int32(v)))
	}
	return out, nil
}

// AssembleCode assembles code+rdata+data with no named sections (the
// PICO child path); resource markers are an error here.
func (l *Linker) AssembleCode() ([]byte, error) {
	return l.Assemble(nil, nil)
}

// SymbolOffset returns a global's final blob offset after Assemble.
func (l *Linker) SymbolOffset(name string) (int, bool) {
	off, ok := l.final[name]
	return off, ok
}
