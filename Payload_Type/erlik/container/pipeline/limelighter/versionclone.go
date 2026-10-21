package limelighter

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/josephspurrier/goversioninfo"
)

// Resource types cloned from a donor PE.
const (
	rtIcon      = 3
	rtGroupIcon = 14
	rtVersion   = 16
)

// CloneFileProperties copies the version resource and icon from a donor PE
// into fart.syso for the current loader workspace. It mirrors FileProperties
// and RandomFileProperties: same output file, same return contract. The
// workspace name is kept so output naming stays predictable.
func CloneFileProperties(name, donorPath string) string {
	fmt.Println("[*] Cloning version resource from donor PE")
	data, used, err := readDonor(donorPath)
	if err != nil {
		log.Fatalf("Error: %s", err)
	}
	img, err := parsePEResources(data)
	if err != nil {
		log.Fatalf("Error: donor %s is not a valid PE: %s", used, err)
	}
	blob, err := img.resource(rtVersion)
	if err != nil {
		log.Fatalf("Error: no version resource found in donor %s", used)
	}
	vi, err := parseVersionResource(blob)
	if err != nil {
		log.Fatalf("Error: cannot parse version resource in donor %s: %s", used, err)
	}
	if group, err := img.resource(rtGroupIcon); err != nil {
		fmt.Println("[*] Donor has no icon; cloning version info only")
	} else if icon, err := buildICO(group, img.iconResource); err != nil {
		fmt.Printf("[!] WARNING: donor icon skipped: %s\n", err)
	} else if err := os.WriteFile("donor.ico", icon, 0666); err != nil {
		log.Fatalf("Error writing donor.ico: %s", err)
	} else {
		vi.IconPath = "donor.ico"
		fmt.Println("[+] Cloned icon from donor PE")
	}

	vi.Build()
	vi.Walk()

	if err := vi.WriteSyso("fart.syso", "amd64"); err != nil {
		log.Printf("Error writing syso: %v", err)
		os.Exit(3)
	}
	fmt.Println("[+] Cloned version resource from " + used)
	return name
}

// readDonor reads the donor PE. execute() runs inside the loader workspace,
// so a path relative to the repo root needs the same "../" prefix that
// FileProperties applies to -configfile.
func readDonor(donorPath string) ([]byte, string, error) {
	candidates := []string{donorPath}
	if !filepath.IsAbs(donorPath) && !strings.HasPrefix(donorPath, "../") {
		candidates = append(candidates, filepath.Join("..", donorPath))
	}
	for _, c := range candidates {
		if data, err := os.ReadFile(c); err == nil {
			return data, c, nil
		}
	}
	return nil, "", fmt.Errorf("cannot read donor PE %s", donorPath)
}

type peSection struct {
	vaddr  uint32
	vsize  uint32
	rawPtr uint32
	rawLen uint32
}

type peImage struct {
	data     []byte
	sections []peSection
	rsrcRVA  uint32
	rsrcLen  uint32
}

// peHeaderLoc locates the COFF and optional headers of a PE image.
// Every read is bounds-checked for untrusted donor input.
func peHeaderLoc(data []byte) (peOff, optOff, optSize int, magic uint16, err error) {
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		return 0, 0, 0, 0, fmt.Errorf("bad DOS header")
	}
	peOff = int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if peOff < 0 || peOff+24 > len(data) || data[peOff] != 'P' || data[peOff+1] != 'E' {
		return 0, 0, 0, 0, fmt.Errorf("bad PE signature")
	}
	optSize = int(binary.LittleEndian.Uint16(data[peOff+20 : peOff+22]))
	optOff = peOff + 24
	if optOff+optSize > len(data) {
		return 0, 0, 0, 0, fmt.Errorf("bad COFF header")
	}
	magic = binary.LittleEndian.Uint16(data[optOff : optOff+2])
	if magic != 0x10b && magic != 0x20b {
		return 0, 0, 0, 0, fmt.Errorf("unknown optional magic %#x", magic)
	}
	return peOff, optOff, optSize, magic, nil
}

// parsePEResources maps the section table and resource data directory of a
// 32- or 64-bit PE. Every read is bounds-checked for untrusted donor input.
func parsePEResources(data []byte) (*peImage, error) {
	peOff, optOff, sizeOfOpt, magic, err := peHeaderLoc(data)
	if err != nil {
		return nil, err
	}
	numSections := int(binary.LittleEndian.Uint16(data[peOff+6 : peOff+8]))
	if numSections < 0 || numSections > 96 {
		return nil, fmt.Errorf("bad COFF header")
	}
	var dirOff int
	if magic == 0x10b {
		dirOff = optOff + 96
	} else {
		dirOff = optOff + 112
	}
	if dirOff+24 > optOff+sizeOfOpt {
		return nil, fmt.Errorf("no resource directory")
	}
	img := &peImage{
		data:     data,
		rsrcRVA:  binary.LittleEndian.Uint32(data[dirOff+16 : dirOff+20]),
		rsrcLen:  binary.LittleEndian.Uint32(data[dirOff+20 : dirOff+24]),
		sections: make([]peSection, 0, numSections),
	}
	tabOff := optOff + sizeOfOpt
	if tabOff+40*numSections > len(data) {
		return nil, fmt.Errorf("bad section table")
	}
	for i := 0; i < numSections; i++ {
		e := tabOff + i*40
		img.sections = append(img.sections, peSection{
			vsize:  binary.LittleEndian.Uint32(data[e+8 : e+12]),
			vaddr:  binary.LittleEndian.Uint32(data[e+12 : e+16]),
			rawLen: binary.LittleEndian.Uint32(data[e+16 : e+20]),
			rawPtr: binary.LittleEndian.Uint32(data[e+20 : e+24]),
		})
	}
	return img, nil
}

// certDirEntry locates the certificate data directory entry (index 4) and
// returns its file offset, size, and the entry's own file offset for
// patching. Unlike other directories the certificate "RVA" is a raw file
// offset, so no section mapping is needed.
func certDirEntry(data []byte) (certOff, certSize uint32, entryOff int, err error) {
	_, optOff, optSize, magic, err := peHeaderLoc(data)
	if err != nil {
		return 0, 0, 0, err
	}
	var dirOff, countOff int
	if magic == 0x10b {
		dirOff, countOff = optOff+96, optOff+92
	} else {
		dirOff, countOff = optOff+112, optOff+108
	}
	if binary.LittleEndian.Uint32(data[countOff:countOff+4]) < 5 || dirOff+40 > optOff+optSize {
		return 0, 0, 0, fmt.Errorf("no certificate directory")
	}
	entryOff = dirOff + 32
	certOff = binary.LittleEndian.Uint32(data[entryOff : entryOff+4])
	certSize = binary.LittleEndian.Uint32(data[entryOff+4 : entryOff+8])
	return certOff, certSize, entryOff, nil
}

// rvaToOffset maps a relative virtual address to a file offset.
func (img *peImage) rvaToOffset(rva uint32) (int, bool) {
	for _, s := range img.sections {
		span := s.vsize
		if s.rawLen > span {
			span = s.rawLen
		}
		if rva >= s.vaddr && rva < s.vaddr+span {
			off := int(s.rawPtr + (rva - s.vaddr))
			if off >= 0 && off < len(img.data) {
				return off, true
			}
		}
	}
	return 0, false
}

type rsrcEntry struct {
	id    uint32
	named bool
	isDir bool
	off   int // offset relative to resource section start
}

// dirEntries reads one IMAGE_RESOURCE_DIRECTORY at an absolute file offset.
func (img *peImage) dirEntries(dirOff int) ([]rsrcEntry, error) {
	if dirOff < 0 || dirOff+16 > len(img.data) {
		return nil, fmt.Errorf("resource directory out of bounds")
	}
	total := int(binary.LittleEndian.Uint16(img.data[dirOff+12:dirOff+14])) +
		int(binary.LittleEndian.Uint16(img.data[dirOff+14:dirOff+16]))
	if dirOff+16+8*total > len(img.data) {
		return nil, fmt.Errorf("resource entries out of bounds")
	}
	out := make([]rsrcEntry, 0, total)
	for i := 0; i < total; i++ {
		e := dirOff + 16 + i*8
		nameOrID := binary.LittleEndian.Uint32(img.data[e : e+4])
		dataOff := binary.LittleEndian.Uint32(img.data[e+4 : e+8])
		out = append(out, rsrcEntry{
			id:    nameOrID & 0x7fffffff,
			named: nameOrID&0x80000000 != 0,
			isDir: dataOff&0x80000000 != 0,
			off:   int(dataOff & 0x7fffffff),
		})
	}
	return out, nil
}

// leafData resolves an IMAGE_RESOURCE_DATA_ENTRY to its raw bytes.
func (img *peImage) leafData(rsrcOff int, e rsrcEntry) ([]byte, error) {
	abs := rsrcOff + e.off
	if abs < 0 || abs+16 > len(img.data) {
		return nil, fmt.Errorf("resource data entry out of bounds")
	}
	rva := binary.LittleEndian.Uint32(img.data[abs : abs+4])
	size := binary.LittleEndian.Uint32(img.data[abs+4 : abs+8])
	off, ok := img.rvaToOffset(rva)
	if !ok || off+int(size) > len(img.data) {
		return nil, fmt.Errorf("resource data out of bounds")
	}
	return img.data[off : off+int(size)], nil
}

// resource returns the first leaf under a resource type: type -> name ->
// language. Name and language levels take the first entry, which matches
// what Windows loads by default.
func (img *peImage) resource(typeID uint32) ([]byte, error) {
	if img.rsrcRVA == 0 {
		return nil, fmt.Errorf("no resources")
	}
	rsrcOff, ok := img.rvaToOffset(img.rsrcRVA)
	if !ok {
		return nil, fmt.Errorf("resource section unmapped")
	}
	types, err := img.dirEntries(rsrcOff)
	if err != nil {
		return nil, err
	}
	for _, t := range types {
		if t.named || t.id != typeID || !t.isDir {
			continue
		}
		names, err := img.dirEntries(rsrcOff + t.off)
		if err != nil || len(names) == 0 {
			return nil, fmt.Errorf("empty name level")
		}
		n := names[0]
		if !n.isDir {
			return img.leafData(rsrcOff, n)
		}
		langs, err := img.dirEntries(rsrcOff + n.off)
		if err != nil || len(langs) == 0 {
			return nil, fmt.Errorf("empty language level")
		}
		if langs[0].isDir {
			return nil, fmt.Errorf("resource tree too deep")
		}
		return img.leafData(rsrcOff, langs[0])
	}
	return nil, fmt.Errorf("resource type %d not found", typeID)
}

// iconResource returns the RT_ICON leaf with the given numeric ID.
func (img *peImage) iconResource(id uint16) ([]byte, error) {
	if img.rsrcRVA == 0 {
		return nil, fmt.Errorf("no resources")
	}
	rsrcOff, ok := img.rvaToOffset(img.rsrcRVA)
	if !ok {
		return nil, fmt.Errorf("resource section unmapped")
	}
	types, err := img.dirEntries(rsrcOff)
	if err != nil {
		return nil, err
	}
	for _, t := range types {
		if t.named || t.id != rtIcon || !t.isDir {
			continue
		}
		names, err := img.dirEntries(rsrcOff + t.off)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			if n.named || n.id != uint32(id) {
				continue
			}
			if !n.isDir {
				return img.leafData(rsrcOff, n)
			}
			langs, err := img.dirEntries(rsrcOff + n.off)
			if err != nil || len(langs) == 0 || langs[0].isDir {
				return nil, fmt.Errorf("bad icon language level")
			}
			return img.leafData(rsrcOff, langs[0])
		}
		return nil, fmt.Errorf("icon %d not found", id)
	}
	return nil, fmt.Errorf("no icons")
}

// buildICO rebuilds a .ico file from an RT_GROUP_ICON blob, resolving each
// image through the RT_ICON resources.
func buildICO(group []byte, lookup func(uint16) ([]byte, error)) ([]byte, error) {
	if len(group) < 6 || binary.LittleEndian.Uint16(group[2:4]) != 1 {
		return nil, fmt.Errorf("bad group icon header")
	}
	count := int(binary.LittleEndian.Uint16(group[4:6]))
	if count == 0 || len(group) < 6+14*count {
		return nil, fmt.Errorf("bad group icon entries")
	}
	type img struct {
		header [16]byte
		data   []byte
	}
	images := make([]img, 0, count)
	off := 6 + 16*count
	for i := 0; i < count; i++ {
		e := group[6+i*14 : 6+(i+1)*14]
		data, err := lookup(binary.LittleEndian.Uint16(e[12:14]))
		if err != nil {
			return nil, err
		}
		var h [16]byte
		copy(h[:8], e[:8])
		binary.LittleEndian.PutUint32(h[8:12], uint32(len(data)))
		binary.LittleEndian.PutUint32(h[12:16], uint32(off))
		images = append(images, img{header: h, data: data})
		off += len(data)
	}
	out := make([]byte, 0, off)
	out = append(out, 0, 0, 1, 0, byte(count), byte(count>>8))
	for _, im := range images {
		out = append(out, im.header[:]...)
	}
	for _, im := range images {
		out = append(out, im.data...)
	}
	return out, nil
}

// verBlock is one VS_VERSIONINFO-style block: header, UTF-16 key, value,
// then children packed inside wLength.
type verBlock struct {
	key      string
	typ      uint16
	valOff   int
	valWords uint16
	kidsOff  int
	end      int
}

func utf16ToString(b []byte) string {
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		v := binary.LittleEndian.Uint16(b[i : i+2])
		if v == 0 {
			break
		}
		u16 = append(u16, v)
	}
	return string(utf16.Decode(u16))
}

// parseVerBlock reads the block starting at off, bounded by end.
func parseVerBlock(buf []byte, off, end int) (verBlock, int, error) {
	var b verBlock
	if off < 0 || off+6 > end || off+6 > len(buf) {
		return b, 0, fmt.Errorf("block header out of bounds")
	}
	wLen := int(binary.LittleEndian.Uint16(buf[off : off+2]))
	b.valWords = binary.LittleEndian.Uint16(buf[off+2 : off+4])
	b.typ = binary.LittleEndian.Uint16(buf[off+4 : off+6])
	if wLen < 6 || off+wLen > end || off+wLen > len(buf) {
		return b, 0, fmt.Errorf("bad block length")
	}
	b.end = off + wLen
	keyEnd := -1
	for i := off + 6; i+1 < b.end; i += 2 {
		if buf[i] == 0 && buf[i+1] == 0 {
			keyEnd = i + 2
			break
		}
	}
	if keyEnd < 0 {
		return b, 0, fmt.Errorf("unterminated block key")
	}
	b.key = utf16ToString(buf[off+6 : keyEnd])
	b.valOff = (keyEnd + 3) &^ 3
	var valLen int
	if b.typ == 1 {
		valLen = int(b.valWords) * 2
	} else {
		valLen = int(b.valWords)
	}
	if b.valOff+valLen > b.end {
		return b, 0, fmt.Errorf("block value out of bounds")
	}
	b.kidsOff = (b.valOff + valLen + 3) &^ 3
	next := (b.end + 3) &^ 3
	if next > end {
		next = end
	}
	return b, next, nil
}

// kids iterates the child blocks of b.
func kids(buf []byte, b verBlock) ([]verBlock, error) {
	var out []verBlock
	for off := b.kidsOff; off+6 <= b.end; {
		cb, next, err := parseVerBlock(buf, off, b.end)
		if err != nil {
			return nil, err
		}
		out = append(out, cb)
		if next <= off {
			break
		}
		off = next
	}
	return out, nil
}

func splitVersion(v uint32) goversioninfo.FileVersion {
	return goversioninfo.FileVersion{
		Major: int(v >> 16),
		Minor: int(v & 0xffff),
	}
}

func joinVersion(hi, lo uint32) goversioninfo.FileVersion {
	fv := splitVersion(hi)
	fv.Patch = int(lo >> 16)
	fv.Build = int(lo & 0xffff)
	return fv
}

// parseVersionResource converts an RT_VERSION blob into goversioninfo input.
// Fixed versions come from VS_FIXEDFILEINFO; strings stay verbatim.
// ponytail: goversioninfo emits one string table with 12 fixed keys, so extra
// donor tables and custom keys are dropped; forking the dep would lift this.
func parseVersionResource(blob []byte) (*goversioninfo.VersionInfo, error) {
	top, _, err := parseVerBlock(blob, 0, len(blob))
	if err != nil {
		return nil, err
	}
	if top.key != "VS_VERSION_INFO" {
		return nil, fmt.Errorf("not a version resource")
	}
	vi := &goversioninfo.VersionInfo{}
	if top.typ == 0 && top.valWords >= 52 {
		fixed := blob[top.valOff : top.valOff+52]
		if binary.LittleEndian.Uint32(fixed[0:4]) != 0xFEEF04BD {
			return nil, fmt.Errorf("bad fixed signature")
		}
		vi.FixedFileInfo.FileVersion = joinVersion(
			binary.LittleEndian.Uint32(fixed[8:12]),
			binary.LittleEndian.Uint32(fixed[12:16]))
		vi.FixedFileInfo.ProductVersion = joinVersion(
			binary.LittleEndian.Uint32(fixed[16:20]),
			binary.LittleEndian.Uint32(fixed[20:24]))
		hex := func(v uint32) string { return strconv.FormatUint(uint64(v), 16) }
		vi.FixedFileInfo.FileFlagsMask = hex(binary.LittleEndian.Uint32(fixed[24:28]))
		vi.FixedFileInfo.FileFlags = hex(binary.LittleEndian.Uint32(fixed[28:32]))
		vi.FixedFileInfo.FileOS = hex(binary.LittleEndian.Uint32(fixed[32:36]))
		vi.FixedFileInfo.FileType = hex(binary.LittleEndian.Uint32(fixed[36:40]))
		vi.FixedFileInfo.FileSubType = hex(binary.LittleEndian.Uint32(fixed[40:44]))
	}
	sections, err := kids(blob, top)
	if err != nil {
		return nil, err
	}
	for _, s := range sections {
		if s.key != "StringFileInfo" {
			continue
		}
		tables, err := kids(blob, s)
		if err != nil || len(tables) == 0 {
			return nil, fmt.Errorf("bad string tables")
		}
		t := tables[0]
		if len(t.key) == 8 {
			if lang, err1 := strconv.ParseUint(t.key[:4], 16, 16); err1 == nil {
				if cs, err2 := strconv.ParseUint(t.key[4:], 16, 16); err2 == nil {
					vi.VarFileInfo.Translation.LangID = goversioninfo.LangID(lang)
					vi.VarFileInfo.Translation.CharsetID = goversioninfo.CharsetID(cs)
				}
			}
		}
		strs, err := kids(blob, t)
		if err != nil {
			return nil, err
		}
		for _, st := range strs {
			val := utf16ToString(blob[st.valOff:st.end])
			switch st.key {
			case "Comments":
				vi.StringFileInfo.Comments = val
			case "CompanyName":
				vi.StringFileInfo.CompanyName = val
			case "FileDescription":
				vi.StringFileInfo.FileDescription = val
			case "FileVersion":
				vi.StringFileInfo.FileVersion = val
			case "InternalName":
				vi.StringFileInfo.InternalName = val
			case "LegalCopyright":
				vi.StringFileInfo.LegalCopyright = val
			case "LegalTrademarks":
				vi.StringFileInfo.LegalTrademarks = val
			case "OriginalFilename":
				vi.StringFileInfo.OriginalFilename = val
			case "PrivateBuild":
				vi.StringFileInfo.PrivateBuild = val
			case "ProductName":
				vi.StringFileInfo.ProductName = val
			case "ProductVersion":
				vi.StringFileInfo.ProductVersion = val
			case "SpecialBuild":
				vi.StringFileInfo.SpecialBuild = val
			}
		}
	}
	return vi, nil
}
