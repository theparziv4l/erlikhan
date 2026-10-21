package peutils

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"erlik/pipeline/cryptor"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func PEStomp(name string) {
	data, err := os.ReadFile(name)
	if err != nil {
		log.Fatalf("PEStomp: error reading %s: %s", name, err)
	}

	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		fmt.Println("[!] PEStomp: not a valid PE file, skipping")
		return
	}

	peOffset := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if peOffset+24 > len(data) {
		fmt.Println("[!] PEStomp: invalid PE offset, skipping")
		return
	}

	if data[peOffset] != 'P' || data[peOffset+1] != 'E' {
		fmt.Println("[!] PEStomp: invalid PE signature, skipping")
		return
	}

	// Zero Rich header: scan between DOS header end and PE header
	// (0x40, not 0x80: Go/LLD stubs are shorter than MSVC's).
	richEnd := -1
	for i := 0x40; i < peOffset-4; i++ {
		if data[i] == 'R' && data[i+1] == 'i' && data[i+2] == 'c' && data[i+3] == 'h' {
			richEnd = i + 8 // Rich + checksum (4 bytes)
			break
		}
	}
	if richEnd > 0 {
		// Find DanS marker working backwards
		richChecksum := binary.LittleEndian.Uint32(data[richEnd-4 : richEnd])
		dansStart := -1
		for i := 0x40; i < richEnd; i++ {
			val := binary.LittleEndian.Uint32(data[i : i+4])
			if val^richChecksum == 0x536E6144 { // "DanS" XOR'd
				dansStart = i
				break
			}
		}
		if dansStart > 0 {
			fmt.Println("[*] PEStomp: zeroing Rich header")
			for i := dansStart; i < richEnd; i++ {
				data[i] = 0
			}
		}
	}

	// Randomize TimeDateStamp in COFF header
	fmt.Println("[*] PEStomp: randomizing PE timestamp")
	tsOffset := peOffset + 8
	randTS := make([]byte, 4)
	rand.Read(randTS)
	// Set to a plausible range: 2020-2025 epoch range
	// 1577836800 (2020-01-01) to 1735689600 (2025-01-01)
	tsVal := uint32(1577836800 + (binary.LittleEndian.Uint32(randTS) % (1735689600 - 1577836800)))
	binary.LittleEndian.PutUint32(data[tsOffset:tsOffset+4], tsVal)

	// Spoof linker version to match MSVC 14.x
	fmt.Println("[*] PEStomp: spoofing linker version to MSVC 14.x")
	optHeaderOffset := peOffset + 24
	if optHeaderOffset+2 <= len(data) {
		data[optHeaderOffset+2] = 14                          // MajorLinkerVersion
		data[optHeaderOffset+3] = byte(20 + (randTS[0] % 20)) // MinorLinkerVersion 20-39
	}

	// Zero debug directory if present
	// For PE32+, debug dir RVA is at optional header offset + 144 (0x90)
	optMagic := binary.LittleEndian.Uint16(data[optHeaderOffset : optHeaderOffset+2])
	var debugDirOffset int
	if optMagic == 0x20b { // PE32+
		debugDirOffset = optHeaderOffset + 144
	} else if optMagic == 0x10b { // PE32
		debugDirOffset = optHeaderOffset + 128
	}
	if debugDirOffset > 0 && debugDirOffset+8 <= len(data) {
		debugRVA := binary.LittleEndian.Uint32(data[debugDirOffset : debugDirOffset+4])
		debugSize := binary.LittleEndian.Uint32(data[debugDirOffset+4 : debugDirOffset+8])
		if debugRVA > 0 && debugSize > 0 {
			fmt.Println("[*] PEStomp: zeroing debug directory entry")
			binary.LittleEndian.PutUint32(data[debugDirOffset:debugDirOffset+4], 0)
			binary.LittleEndian.PutUint32(data[debugDirOffset+4:debugDirOffset+8], 0)
		}
	}

	// Zero .buildid section content if present.
	zeroBuildID(data, peOffset)

	// Rename Go/toolchain section names to MSVC-neutral equivalents.
	renameSections(data, peOffset, true)

	// Fix PE checksum
	FixPEChecksum(data, peOffset)

	if err := os.WriteFile(name, data, 0777); err != nil {
		log.Fatalf("PEStomp: error writing %s: %s", name, err)
	}
	fmt.Println("[+] PE metadata stomped successfully")
}

func FixPEChecksum(data []byte, peOffset int) {
	// Zero existing checksum first
	checksumOffset := peOffset + 24 + 64 // OptionalHeader + 64 bytes to checksum field
	if checksumOffset+4 > len(data) {
		return
	}
	binary.LittleEndian.PutUint32(data[checksumOffset:checksumOffset+4], 0)

	// Calculate new checksum (PE checksum algorithm)
	var checksum uint64
	for i := 0; i < len(data)/2; i++ {
		if i*2 == checksumOffset || i*2 == checksumOffset+2 {
			continue
		}
		val := uint64(binary.LittleEndian.Uint16(data[i*2 : i*2+2]))
		checksum += val
		if checksum > 0xFFFFFFFF {
			checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)
		}
	}
	if len(data)%2 != 0 {
		checksum += uint64(data[len(data)-1])
	}
	checksum = (checksum & 0xFFFF) + (checksum >> 16)
	checksum += checksum >> 16
	checksum = (checksum & 0xFFFF) + uint64(len(data))

	binary.LittleEndian.PutUint32(data[checksumOffset:checksumOffset+4], uint32(checksum))
}

// sectionRename maps toolchain-specific section names to MSVC-neutral
// equivalents. Load-critical sections (.text .data .rdata .reloc .rsrc
// .pdata .xdata) are never renamed. Names over 8 bytes never survive the
// section header intact, so truncated forms match too.
func sectionRename(name string) string {
	name = string(bytes.TrimRight([]byte(name), "\x00"))
	switch {
	case name == ".symtab" || name == ".gosymtab" || name == ".gosymta":
		return ".debug"
	case name == ".noptrbss" || name == ".noptrbs":
		return ".bss"
	case name == ".noptrdata" || name == ".noptrdat":
		return ".data"
	case name == ".gopclntab" || name == ".gopclnt" ||
		name == ".typelink" || name == ".typelin" ||
		name == ".itablink" || name == ".itablin":
		return ".rdata"
	case name == ".rodata":
		return ".rdata"
	case name == ".note.go.buildid" || name == ".note.go" || name == ".note":
		return ".buildid"
	default:
		return ""
	}
}

func sectionTable(data []byte, peOffset int) (numSections, tableOffset int, ok bool) {
	if peOffset+24 > len(data) {
		return 0, 0, false
	}
	numSections = int(binary.LittleEndian.Uint16(data[peOffset+6 : peOffset+8]))
	sizeOfOptHeader := int(binary.LittleEndian.Uint16(data[peOffset+20 : peOffset+22]))
	tableOffset = peOffset + 24 + sizeOfOptHeader
	if numSections <= 0 || numSections > 96 {
		return 0, 0, false
	}
	return numSections, tableOffset, true
}

func zeroBuildID(data []byte, peOffset int) {
	numSections, tableOffset, ok := sectionTable(data, peOffset)
	if !ok {
		return
	}
	for i := 0; i < numSections; i++ {
		secOffset := tableOffset + (i * 40)
		if secOffset+40 > len(data) {
			break
		}
		secName := string(data[secOffset : secOffset+8])
		if secName[:8] == ".buildid" || secName[:7] == ".buildi" {
			fmt.Println("[*] PEStomp: zeroing .buildid section")
			rawOffset := int(binary.LittleEndian.Uint32(data[secOffset+20 : secOffset+24]))
			rawSize := int(binary.LittleEndian.Uint32(data[secOffset+16 : secOffset+20]))
			if rawOffset > 0 && rawSize > 0 && rawOffset+rawSize <= len(data) {
				randData := make([]byte, rawSize)
				rand.Read(randData)
				copy(data[rawOffset:rawOffset+rawSize], randData)
			}
		}
	}
}

func renameSections(data []byte, peOffset int, verbose bool) {
	numSections, tableOffset, ok := sectionTable(data, peOffset)
	if !ok {
		return
	}
	for i := 0; i < numSections; i++ {
		secOffset := tableOffset + (i * 40)
		if secOffset+40 > len(data) {
			break
		}
		if newName := sectionRename(string(data[secOffset : secOffset+8])); newName != "" {
			if verbose {
				fmt.Printf("[*] Renaming section %.8s -> %s\n", string(data[secOffset:secOffset+8]), newName)
			}
			for j := 0; j < 8; j++ {
				data[secOffset+j] = 0
			}
			copy(data[secOffset:secOffset+8], newName)
		}
	}
}

// RenameSections rewrites toolchain-specific section names in place and
// fixes the PE checksum. Safe no-op on invalid input.
func RenameSections(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("[!] RenameSections: error reading %s: %s\n", path, err)
		return
	}
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		fmt.Println("[!] RenameSections: not a valid PE file, skipping")
		return
	}
	peOffset := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if peOffset+24 > len(data) || data[peOffset] != 'P' || data[peOffset+1] != 'E' {
		fmt.Println("[!] RenameSections: invalid PE signature, skipping")
		return
	}
	renameSections(data, peOffset, true)
	FixPEChecksum(data, peOffset)
	if err := os.WriteFile(path, data, 0777); err != nil {
		log.Fatalf("RenameSections: error writing %s: %s", path, err)
	}
}

// UniquifyPE randomizes the TimeDateStamp, appends 16-64 random overlay
// bytes, and fixes the PE checksum so each build hashes differently.
// Invalid PE input returns an error; it never calls log.Fatal.
func UniquifyPE(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("UniquifyPE: error reading %s: %w", path, err)
	}
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		return fmt.Errorf("UniquifyPE: %s is not a valid PE file", path)
	}
	peOffset := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if peOffset+24 > len(data) || data[peOffset] != 'P' || data[peOffset+1] != 'E' {
		return fmt.Errorf("UniquifyPE: %s has an invalid PE signature", path)
	}

	// Randomize TimeDateStamp in COFF header, same plausible range as PEStomp:
	// 1577836800 (2020-01-01) to 1735689600 (2025-01-01).
	tsOffset := peOffset + 8
	randTS := make([]byte, 4)
	if _, err := rand.Read(randTS); err != nil {
		return fmt.Errorf("UniquifyPE: random timestamp: %w", err)
	}
	tsVal := uint32(1577836800 + (binary.LittleEndian.Uint32(randTS) % (1735689600 - 1577836800)))
	binary.LittleEndian.PutUint32(data[tsOffset:tsOffset+4], tsVal)

	// Append 16-64 random overlay bytes.
	var lenBuf [1]byte
	if _, err := rand.Read(lenBuf[:]); err != nil {
		return fmt.Errorf("UniquifyPE: random overlay size: %w", err)
	}
	overlay := make([]byte, 16+int(lenBuf[0]%49))
	if _, err := rand.Read(overlay); err != nil {
		return fmt.Errorf("UniquifyPE: random overlay: %w", err)
	}
	data = append(data, overlay...)

	FixPEChecksum(data, peOffset)

	if err := os.WriteFile(path, data, 0777); err != nil {
		return fmt.Errorf("UniquifyPE: error writing %s: %w", path, err)
	}
	fmt.Println("[+] PE uniquified successfully")
	return nil
}

// StripBinary runs the first available PE-aware strip tool with -s,
// removing symbol tables and debug info. Must run before signing.
func StripBinary(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	tools := []string{"x86_64-w64-mingw32-strip", "llvm-strip", "strip"}
	for _, tool := range tools {
		bin, err := exec.LookPath(tool)
		if err != nil {
			continue
		}
		cmd := exec.Command(bin, "-s", path)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s -s failed: %v: %s", tool, err, stderr.String())
		}
		fmt.Printf("[*] Stripped symbols with %s -s\n", tool)
		return nil
	}
	return fmt.Errorf("no strip tool found (tried %s)", "x86_64-w64-mingw32-strip, llvm-strip, strip")
}

// ponytail: UPX only; custom packer (xor stub + loader) when UPX-stub
// signatures get flagged.
// PackUPX compresses the binary with UPX --best. Runs after strip/rename
// and before signing. Mode "none"/"" skips.
func PackUPX(path, mode string) error {
	if mode == "" || mode == "none" {
		return nil
	}
	if mode != "upx" {
		return fmt.Errorf("unknown pack mode %q (want upx or none)", mode)
	}
	bin, err := exec.LookPath("upx")
	if err != nil {
		return fmt.Errorf("upx not installed: %w", err)
	}
	cmd := exec.Command(bin, "--best", "-q", "--no-backup", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("upx failed: %v: %s", err, stderr.String())
	}
	fmt.Println("[*] Packed with UPX --best")
	return nil
}

// goScrubBasic holds the default Go toolchain fingerprint strings replaced by
// GoEditor. Patterns stay long and distinctive: 4-character fragments such as
// "gogo", "goid" or "glob" also match inside base64/hex payload data and would
// silently corrupt encoded API names or shellcode, so they are excluded here.
var goScrubBasic = []string{
	"to unallocated span37252902984619140625Arabic Standard TimeAzores Standard",
	"TimeCertFindChainInStoreCertOpenSystemStoreWChangeServiceConfigWCheckTokenMembershipCreateProcessAsUserWCryptAcquireContextWEgyptian_HieroglyphsEtwReplyNotificationGetAcceptExSockaddrsGetAdaptersAddressesGetCurrentDirectoryWGetFileAttributesExWGetModuleInformationGetProcessMemoryInfoGetWindowsDirectoryWIDS_Trinary_OperatorIsrael Standard TimeJordan Standard TimeMeroitic_Hieroglyphs",
	"Standard Timebad defer size classbad font file formatbad system page sizebad use of bucket.bpbad use of bucket.mpchan send (nil chan)close of nil channelconnection timed outdodeltimer0: wrong Pfloating point errorforcegc: phase errorgo of nil func valuegopark: bad g statusinconsistent lockedminvalid request",
	"codeinvalid write resultis a named type filekey has been revokedmalloc during signalnotetsleep not on g0p mcache not flushedpacer: assist ratio=preempt off reason: reflect.Value.SetIntreflect.makeFuncStubruntime: double waitruntime: unknown pc semaRoot rotateRighttime: invalid numbertrace: out of memorywirep: already in goworkbuf is not emptywrite of Go pointer ws2_32.dll not foundzlib: invalid header of unexported method previous allocCount=, levelBits[level] = 186264514923095703125931322574615478515625AdjustTokenPrivilegesAlaskan Standard TimeAnatolian_HieroglyphsArabian Standard TimeBelarus Standard TimeCentral Standard TimeChangeServiceConfig2WDeregisterEventSourceEastern Standard",
	"0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memory",
	"buildinf:",
	" Go build ID:",
	"go.buildid",
	"_cgo_dummy_export",
	"fatal error: cgo callback before cgo cal",
}

func scrubFilePatterns(name string, patterns []string) {
	buff, err := os.ReadFile(name)
	if err != nil {
		log.Fatalf("Error: %s", err)
	}
	mydata := string(buff)
	for _, pattern := range patterns {
		val := cryptor.RandStringBytes(len(pattern))
		mydata = strings.ReplaceAll(mydata, pattern, val)
	}
	if err := os.WriteFile(name, []byte(mydata), 0777); err != nil {
		log.Fatalf("Error writing file %s: %s", name, err)
	}
}

func GoEditor(name string) {
	scrubFilePatterns(name, goScrubBasic)
}

func GoEditorExtended(name string) {
	scrubFilePatterns(name, goScrubBasic)

	extendedPatterns := []string{
		"runtime.goexit",
		"runtime.morestack",
		"runtime.newproc",
		"runtime.gopanic",
		"runtime.gorecover",
		"runtime.deferreturn",
		"runtime.newobject",
		"runtime.makeslice",
		"runtime.makemap",
		"runtime.growslice",
		"runtime.mapassign",
		"runtime.mapaccess",
		"runtime.convT",
		"runtime.assertI2I",
		"runtime.assertE2I",
		"runtime.panicdottypeI",
		"runtime.printstring",
		"runtime.printint",
		"runtime.printnl",
		"runtime.throw",
		"runtime.gcStart",
		"runtime.mallocgc",
		"runtime.heapBitsSetType",
		"runtime.(*mheap).alloc",
		"runtime.schedinit",
		"runtime.main",
		"runtime.args",
		"runtime.osinit",
		"runtime.check",
		"sync.(*Mutex).Lock",
		"sync.(*Mutex).Unlock",
		"sync.(*WaitGroup)",
		"internal/",
		"go.itab.",
		"go.string.",
		"type..hash.",
		"type..eq.",
		"GOROOT",
		"GOPATH",
		`.go"`,
		"go1.",
		"main.main",
		"main.init",
		"gcWriteBarrier",
		"aeshashbody",
		"addmoduledata",
		"moduledata",
		"runtime.text",
		"runtime.etext",
		"runtime.rodata",
	}

	scrubFilePatterns(name, extendedPatterns)
}

func Unzip(src string, dest string) ([]string, error) {
	var filenames []string
	r, err := zip.OpenReader(src)
	if err != nil {
		return filenames, err
	}
	defer r.Close()
	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return filenames, fmt.Errorf("%s: illegal file path", fpath)
		}
		filenames = append(filenames, fpath)
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return filenames, err
		}
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return filenames, err
		}
		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return filenames, err
		}
	}
	return filenames, nil
}

func Sha256(input string) {
	f, err := os.Open(input)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("[!] Sha256 hash of "+input+": %x\n", h.Sum(nil))
}
