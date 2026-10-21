package peutils

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SanitizePE strips MinGW/toolchain fingerprints from a PE binary:
// Rich header, PE timestamp, linker version, debug directory.
func SanitizePE(pePath string) error {
	data, err := os.ReadFile(pePath)
	if err != nil {
		return fmt.Errorf("read PE: %w", err)
	}
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		return fmt.Errorf("not a valid PE file")
	}

	peOffset := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if peOffset+24 > len(data) || data[peOffset] != 'P' || data[peOffset+1] != 'E' {
		return fmt.Errorf("invalid PE signature")
	}

	// Zero Rich header
	richEnd := -1
	for i := 0x40; i < peOffset-4; i++ {
		if data[i] == 'R' && data[i+1] == 'i' && data[i+2] == 'c' && data[i+3] == 'h' {
			richEnd = i + 8
			break
		}
	}
	if richEnd > 0 {
		richChecksum := binary.LittleEndian.Uint32(data[richEnd-4 : richEnd])
		dansStart := -1
		for i := 0x40; i < richEnd; i++ {
			val := binary.LittleEndian.Uint32(data[i : i+4])
			if val^richChecksum == 0x536E6144 {
				dansStart = i
				break
			}
		}
		if dansStart > 0 {
			fmt.Println("[*] SanitizePE: zeroing Rich header")
			for i := dansStart; i < richEnd; i++ {
				data[i] = 0
			}
		}
	}

	// Zero PE timestamp
	fmt.Println("[*] SanitizePE: zeroing PE timestamp")
	tsOffset := peOffset + 8
	binary.LittleEndian.PutUint32(data[tsOffset:tsOffset+4], 0)

	// Zero linker version
	fmt.Println("[*] SanitizePE: zeroing linker version")
	optHeaderOffset := peOffset + 24
	if optHeaderOffset+4 <= len(data) {
		data[optHeaderOffset+2] = 0
		data[optHeaderOffset+3] = 0
	}

	// Zero debug directory
	optMagic := binary.LittleEndian.Uint16(data[optHeaderOffset : optHeaderOffset+2])
	var debugDirOffset int
	if optMagic == 0x20b {
		debugDirOffset = optHeaderOffset + 144
	} else if optMagic == 0x10b {
		debugDirOffset = optHeaderOffset + 128
	}
	if debugDirOffset > 0 && debugDirOffset+8 <= len(data) {
		debugRVA := binary.LittleEndian.Uint32(data[debugDirOffset : debugDirOffset+4])
		debugSize := binary.LittleEndian.Uint32(data[debugDirOffset+4 : debugDirOffset+8])
		if debugRVA > 0 && debugSize > 0 {
			fmt.Println("[*] SanitizePE: zeroing debug directory")
			binary.LittleEndian.PutUint32(data[debugDirOffset:debugDirOffset+4], 0)
			binary.LittleEndian.PutUint32(data[debugDirOffset+4:debugDirOffset+8], 0)

			fileOff := peRVAToOffset(data, peOffset, debugRVA)
			if fileOff > 0 && int(fileOff)+int(debugSize) <= len(data) {
				for i := fileOff; i < fileOff+int(debugSize); i++ {
					data[i] = 0
				}
			}
		}
	}

	FixPEChecksum(data, peOffset)

	if err := os.WriteFile(pePath, data, 0644); err != nil {
		return fmt.Errorf("write PE: %w", err)
	}
	fmt.Println("[+] PE sanitized: " + pePath)
	return nil
}

func peRVAToOffset(data []byte, peOffset int, rva uint32) int {
	numSections, tableOffset, ok := sectionTable(data, peOffset)
	if !ok {
		return -1
	}
	for i := 0; i < numSections; i++ {
		off := tableOffset + i*40
		if off+40 > len(data) {
			break
		}
		va := binary.LittleEndian.Uint32(data[off+12 : off+16])
		vs := binary.LittleEndian.Uint32(data[off+8 : off+12])
		rawOff := binary.LittleEndian.Uint32(data[off+20 : off+24])
		if rva >= va && rva < va+vs {
			return int(rawOff + (rva - va))
		}
	}
	return -1
}

// peSection holds parsed section info for YARA rule generation.
type peSection struct {
	Name       string
	VirtSize   uint32
	RawSize    uint32
	RawOffset  uint32
	Entropy    float64
	Executable bool
}

func parsePESections(data []byte, peOffset int) []peSection {
	numSections, tableOffset, ok := sectionTable(data, peOffset)
	if !ok {
		return nil
	}
	var sections []peSection
	for i := 0; i < numSections; i++ {
		off := tableOffset + i*40
		if off+40 > len(data) {
			break
		}
		name := strings.TrimRight(string(data[off:off+8]), "\x00")
		vs := binary.LittleEndian.Uint32(data[off+8 : off+12])
		rawSize := binary.LittleEndian.Uint32(data[off+16 : off+20])
		rawOff := binary.LittleEndian.Uint32(data[off+20 : off+24])
		chars := binary.LittleEndian.Uint32(data[off+36 : off+40])

		ent := 0.0
		if rawSize > 0 && int(rawOff)+int(rawSize) <= len(data) {
			ent = shannonEntropy(data[rawOff : rawOff+rawSize])
		}

		sections = append(sections, peSection{
			Name:       name,
			VirtSize:   vs,
			RawSize:    rawSize,
			RawOffset:  rawOff,
			Entropy:    ent,
			Executable: chars&0x20000000 != 0,
		})
	}
	return sections
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	ent := 0.0
	for _, f := range freq {
		if f > 0 {
			p := f / n
			ent -= p * math.Log2(p)
		}
	}
	return ent
}

func extractPEImports(data []byte, peOffset int) []string {
	optHeaderOffset := peOffset + 24
	if optHeaderOffset+2 > len(data) {
		return nil
	}
	optMagic := binary.LittleEndian.Uint16(data[optHeaderOffset : optHeaderOffset+2])

	var importDirOffset int
	if optMagic == 0x20b {
		importDirOffset = optHeaderOffset + 120
	} else if optMagic == 0x10b {
		importDirOffset = optHeaderOffset + 104
	} else {
		return nil
	}
	if importDirOffset+8 > len(data) {
		return nil
	}

	importRVA := binary.LittleEndian.Uint32(data[importDirOffset : importDirOffset+4])
	if importRVA == 0 {
		return nil
	}

	importOff := peRVAToOffset(data, peOffset, importRVA)
	if importOff < 0 {
		return nil
	}

	var imports []string
	for i := 0; i < 256; i++ {
		entryOff := importOff + i*20
		if entryOff+20 > len(data) {
			break
		}
		nameRVA := binary.LittleEndian.Uint32(data[entryOff+12 : entryOff+16])
		if nameRVA == 0 {
			break
		}
		nameOff := peRVAToOffset(data, peOffset, nameRVA)
		if nameOff < 0 {
			continue
		}
		end := nameOff
		for end < len(data) && data[end] != 0 {
			end++
		}
		dllName := strings.ToLower(string(data[nameOff:end]))
		imports = append(imports, dllName)
	}
	return imports
}

// peHeaderOffset validates PE headers and returns e_lfanew.
func peHeaderOffset(data []byte) (int, bool) {
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		return 0, false
	}
	peOffset := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if peOffset < 0 || peOffset+6 > len(data) {
		return 0, false
	}
	if data[peOffset] != 'P' || data[peOffset+1] != 'E' {
		return 0, false
	}
	return peOffset, true
}

// yaraRuleName maps a filename to a valid YARA identifier suffix.
func yaraRuleName(baseName string) string {
	name := strings.TrimSuffix(baseName, filepath.Ext(baseName))
	var b strings.Builder
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	name = b.String()
	if name == "" || name[0] >= '0' && name[0] <= '9' {
		name = "_" + name
	}
	return name
}

// yaraLiteral rejects strings unsafe for a YARA double-quoted literal.
func yaraLiteral(s string) (string, bool) {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '"' || c == '\\' || c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	if s == "" {
		return "", false
	}
	return s, true
}

var yaraMetaEscaper = strings.NewReplacer("\\", "\\\\", "\"", "\\\"")

// GenerateSelfHuntYARA creates a YARA rule matching the built artifact.
// PE files get hash, section, and import conditions; anything else
// (JScript loaders, HTA) gets an exact file-hash rule instead.
func GenerateSelfHuntYARA(pePath, outDir string) (string, error) {
	data, err := os.ReadFile(pePath)
	if err != nil {
		return "", fmt.Errorf("read file for YARA: %w", err)
	}

	sha256Hash := fmt.Sprintf("%x", sha256.Sum256(data))
	md5Hash := fmt.Sprintf("%x", md5.Sum(data))
	fileSize := len(data)
	baseName := filepath.Base(pePath)
	ruleName := yaraRuleName(baseName)
	ts := time.Now().UTC().Format("2006-01-02")

	var rule string
	if peOffset, ok := peHeaderOffset(data); ok {
		rule = selfHuntYARAPE(data, peOffset, ruleName, baseName, ts, sha256Hash, md5Hash, fileSize)
	} else {
		rule = selfHuntYARAFile(ruleName, baseName, ts, sha256Hash, md5Hash, fileSize)
	}

	outPath := filepath.Join(outDir, ruleName+".yar")
	if err := os.WriteFile(outPath, []byte(rule), 0644); err != nil {
		return "", fmt.Errorf("write YARA rule: %w", err)
	}
	fmt.Println("[+] Self-hunt YARA rule: " + outPath)
	return outPath, nil
}

func selfHuntYARAPE(data []byte, peOffset int, ruleName, baseName, ts, sha256Hash, md5Hash string, fileSize int) string {
	sections := parsePESections(data, peOffset)
	imports := extractPEImports(data, peOffset)

	var infoLines []string
	for _, s := range sections {
		infoLines = append(infoLines, fmt.Sprintf(
			"        // Section %-8s  entropy=%.2f  raw_size=%d  executable=%v",
			s.Name, s.Entropy, s.RawSize, s.Executable))
	}

	parts := []string{
		"uint16(0) == 0x5A4D",
		"uint32(uint32(0x3C)) == 0x00004550",
		fmt.Sprintf("filesize > %d and filesize < %d", fileSize-1024, fileSize+1024),
		fmt.Sprintf(`hash.sha256(0, filesize) == "%s"`, sha256Hash),
		fmt.Sprintf(`hash.md5(0, filesize) == "%s"`, md5Hash),
	}
	if len(sections) > 0 {
		parts = append(parts, fmt.Sprintf("pe.number_of_sections == %d", len(sections)))
		for i, s := range sections {
			if lit, ok := yaraLiteral(s.Name); ok {
				parts = append(parts, fmt.Sprintf(`pe.sections[%d].name == "%s"`, i, lit))
			}
		}
	}
	sort.Strings(imports)
	for _, imp := range imports {
		if lit, ok := yaraLiteral(imp); ok {
			parts = append(parts, fmt.Sprintf(`pe.imports("%s")`, lit))
		}
	}
	condition := "        " + strings.Join(parts, " and\n        ")
	if len(infoLines) > 0 {
		condition = strings.Join(infoLines, "\n") + "\n" + condition
	}

	return fmt.Sprintf(`import "pe"
import "hash"

rule SelfHunt_%s
{
    meta:
        description = "Self-hunt rule for Erlikhan artifact: %s"
        date = "%s"
        sha256 = "%s"
        md5 = "%s"
        tool = "Erlikhan"

    condition:
%s
}
`, ruleName, yaraMetaEscaper.Replace(baseName), ts, sha256Hash, md5Hash, condition)
}

func selfHuntYARAFile(ruleName, baseName, ts, sha256Hash, md5Hash string, fileSize int) string {
	parts := []string{
		fmt.Sprintf("filesize == %d", fileSize),
		fmt.Sprintf(`hash.sha256(0, filesize) == "%s"`, sha256Hash),
		fmt.Sprintf(`hash.md5(0, filesize) == "%s"`, md5Hash),
	}
	return fmt.Sprintf(`import "hash"

rule SelfHunt_%s
{
    meta:
        description = "Self-hunt rule for Erlikhan artifact: %s"
        date = "%s"
        sha256 = "%s"
        md5 = "%s"
        tool = "Erlikhan"

    condition:
        %s
}
`, ruleName, yaraMetaEscaper.Replace(baseName), ts, sha256Hash, md5Hash,
		strings.Join(parts, " and\n        "))
}

// sigmaID formats a content hash as a deterministic UUID-shaped rule id.
func sigmaID(sha256Hex string) string {
	h := sha256Hex
	if len(h) < 32 {
		h += strings.Repeat("0", 32-len(h))
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

// GenerateSelfHuntSigma creates a Sigma rule for process-creation detection.
func GenerateSelfHuntSigma(pePath, processName, outDir string) (string, error) {
	data, err := os.ReadFile(pePath)
	if err != nil {
		return "", fmt.Errorf("read file for Sigma: %w", err)
	}

	sha256Hash := fmt.Sprintf("%x", sha256.Sum256(data))
	md5Hash := fmt.Sprintf("%x", md5.Sum(data))
	baseName := filepath.Base(pePath)
	if processName == "" {
		processName = baseName
	}
	yamlQuote := strings.NewReplacer("'", "''")

	ts := time.Now().UTC().Format("2006/01/02")
	ruleName := yaraRuleName(baseName)

	sigma := fmt.Sprintf(`title: Erlikhan Artifact Detection - %s
id: %s
status: experimental
description: Detects execution of Erlikhan-generated payload %s
author: Erlikhan Self-Hunt
date: %s
logsource:
    category: process_creation
    product: windows
detection:
    selection_hash:
        Hashes|contains:
            - '%s'
            - '%s'
    selection_name:
        Image|endswith: '\%s'
    condition: selection_hash or selection_name
falsepositives:
    - Unlikely
level: critical
tags:
    - attack.defense_evasion
    - attack.t1036
`, baseName, sigmaID(sha256Hash), baseName, ts, sha256Hash, md5Hash, yamlQuote.Replace(processName))

	outPath := filepath.Join(outDir, ruleName+".yml")
	if err := os.WriteFile(outPath, []byte(sigma), 0644); err != nil {
		return "", fmt.Errorf("write Sigma rule: %w", err)
	}
	fmt.Println("[+] Self-hunt Sigma rule: " + outPath)
	return outPath, nil
}
