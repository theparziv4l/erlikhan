package palace

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// AMD64 COFF relocation types (subset that matters for PIC objects).
const (
	relAbsolute = 0
	relAddr64   = 1
	relAddr32   = 2
	relAddr32NB = 3
	relRel32    = 4
	relRel32_1  = 5
	relRel32_2  = 6
	relRel32_3  = 7
	relRel32_4  = 8
	relRel32_5  = 9
)

const (
	// Section characteristics.
	scnCntCode         = 0x00000020
	scnCntInitData     = 0x00000040
	scnCntUninitData   = 0x00000080
	scnLnkRemove       = 0x00000800
	scnMemExecute      = 0x20000000
	scnMemRead         = 0x40000000
	scnMemWrite        = 0x80000000
	scnAlignMask       = 0x00F00000
	scnAlignShift      = 20
	storageClassExt    = 2
	storageClassStatic = 3
	storageClassFile   = 103
	symUndef           = 0
	symAbsolute        = -1
	symDebug           = -2
)

// Reloc is one COFF relocation record.
type Reloc struct {
	Offset   uint32
	SymIndex uint32
	Type     uint16
}

// Symbol is one COFF symbol table entry (aux records skipped).
type Symbol struct {
	Name         string
	Value        uint32
	Section      int16 // 1-based, 0 = undefined extern
	StorageClass uint8
}

// Section is one COFF section with materialized data (bss is
// zero-filled so the blob is self-contained).
type Section struct {
	Name            string
	Data            []byte
	Relocs          []Reloc
	Characteristics uint32
}

// Object is a parsed AMD64 COFF relocatable.
type Object struct {
	Sections []Section
	Symbols  []Symbol // index 0 is the null symbol
}

// Alignment returns the section's required alignment in bytes.
func (s *Section) Alignment() int {
	n := (s.Characteristics & scnAlignMask) >> scnAlignShift
	if n == 0 {
		return 1
	}
	a := 1 << (n - 1)
	if a > 32 {
		return 32
	}
	return a
}

func coffString(tab []byte, off uint32) (string, error) {
	if off+4 > uint32(len(tab)) {
		return "", fmt.Errorf("string table offset %d out of range", off)
	}
	// Offsets are relative to the table start, whose first 4 bytes
	// hold the table size.
	end := off
	for end < uint32(len(tab)) && tab[end] != 0 {
		end++
	}
	return string(tab[off:end]), nil
}

// ParseObject parses one AMD64 COFF object file.
func ParseObject(raw []byte) (*Object, error) {
	if len(raw) < 20 {
		return nil, fmt.Errorf("truncated COFF header (%d bytes)", len(raw))
	}
	if m := binary.LittleEndian.Uint16(raw[0:2]); m != 0x8664 {
		return nil, fmt.Errorf("unsupported machine type %#06x (need AMD64)", m)
	}
	numSections := int(binary.LittleEndian.Uint16(raw[2:4]))
	symPtr := binary.LittleEndian.Uint32(raw[8:12])
	numSyms := binary.LittleEndian.Uint32(raw[12:16])
	optSize := int(binary.LittleEndian.Uint16(raw[16:18]))
	if optSize != 0 {
		return nil, fmt.Errorf("COFF has %d optional-header bytes (not an object file)", optSize)
	}
	obj := &Object{}
	for i := 0; i < numSections; i++ {
		off := 20 + i*40
		if off+40 > len(raw) {
			return nil, fmt.Errorf("truncated section header %d", i)
		}
		h := raw[off : off+40]
		name := strings.TrimRight(string(h[0:8]), "\x00")
		size := binary.LittleEndian.Uint32(h[16:20])
		dataPtr := binary.LittleEndian.Uint32(h[20:24])
		relPtr := binary.LittleEndian.Uint32(h[24:28])
		numRel := binary.LittleEndian.Uint16(h[32:34])
		chars := binary.LittleEndian.Uint32(h[36:40])
		if numRel == 0xFFFF {
			return nil, fmt.Errorf("section %q uses extended relocations (unsupported)", name)
		}
		sec := Section{Name: name, Characteristics: chars}
		if chars&scnCntUninitData != 0 {
			// bss: VirtualSize bytes of zeros. VirtualSize sits
			// where SizeOfRawData would be for data sections.
			sec.Data = make([]byte, size)
		} else if size > 0 {
			if uint64(dataPtr)+uint64(size) > uint64(len(raw)) {
				return nil, fmt.Errorf("section %q data out of range", name)
			}
			sec.Data = append([]byte(nil), raw[dataPtr:dataPtr+size]...)
		}
		for r := 0; r < int(numRel); r++ {
			roff := int(relPtr) + r*10
			if roff+10 > len(raw) {
				return nil, fmt.Errorf("truncated relocations in %q", name)
			}
			sec.Relocs = append(sec.Relocs, Reloc{
				Offset:   binary.LittleEndian.Uint32(raw[roff : roff+4]),
				SymIndex: binary.LittleEndian.Uint32(raw[roff+4 : roff+8]),
				Type:     binary.LittleEndian.Uint16(raw[roff+8 : roff+10]),
			})
		}
		obj.Sections = append(obj.Sections, sec)
	}
	// Symbol table.
	end := uint64(symPtr) + uint64(numSyms)*18
	if end > uint64(len(raw)) {
		return nil, fmt.Errorf("truncated symbol table")
	}
	var strTab []byte
	if numSyms > 0 {
		if end+4 > uint64(len(raw)) {
			return nil, fmt.Errorf("truncated string table")
		}
		strSize := binary.LittleEndian.Uint32(raw[end : end+4])
		if strSize < 4 || end+uint64(strSize) > uint64(len(raw)) {
			return nil, fmt.Errorf("string table overruns file")
		}
		strTab = raw[end : end+uint64(strSize)]
	}
	for i := uint32(0); i < numSyms; {
		off := int(symPtr) + int(i)*18
		e := raw[off : off+18]
		var name string
		switch {
		case e[0] == 0 && e[1] == 0 && e[2] == 0 && e[3] == 0 &&
			e[4] == 0 && e[5] == 0 && e[6] == 0 && e[7] == 0:
			name = "" // null symbol
		case binary.LittleEndian.Uint32(e[0:4]) == 0:
			soff := binary.LittleEndian.Uint32(e[4:8])
			var err error
			if name, err = coffString(strTab, soff); err != nil {
				return nil, fmt.Errorf("symbol %d: %w", i, err)
			}
		default:
			name = strings.TrimRight(string(e[0:8]), "\x00")
		}
		aux := int(e[17])
		obj.Symbols = append(obj.Symbols, Symbol{
			Name:         name,
			Value:        binary.LittleEndian.Uint32(e[8:12]),
			Section:      int16(binary.LittleEndian.Uint16(e[12:14])),
			StorageClass: e[16],
		})
		// Aux records occupy symbol slots; repeat the entry shape
		// with empty names so indices stay aligned.
		for a := 0; a < aux; a++ {
			obj.Symbols = append(obj.Symbols, Symbol{})
		}
		i += uint32(1 + aux)
	}
	// Long section names ("/1234") reference the string table.
	for i := range obj.Sections {
		if strings.HasPrefix(obj.Sections[i].Name, "/") {
			var off uint32
			if _, err := fmt.Sscanf(obj.Sections[i].Name, "/%d", &off); err != nil {
				return nil, fmt.Errorf("bad long section name %q", obj.Sections[i].Name)
			}
			long, err := coffString(strTab, off)
			if err != nil {
				return nil, fmt.Errorf("section %d: %w", i, err)
			}
			obj.Sections[i].Name = long
		}
	}
	return obj, nil
}
